from fastapi import (
    FastAPI,
    Request,
    UploadFile,
    File,
    Form,
    BackgroundTasks
)

from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    FileResponse
)

from fastapi.templating import Jinja2Templates

import os
import shutil

from pathlib import Path


from database import (
    SessionLocal,
    ScanHistory,
    User,
    QuarantineFile,
    Base,
    engine
)


from auth import (
    hash_password,
    verify_password,
    create_token,
    decode_token
)


from scanner.hash_scan import get_sha256
from scanner.clamav_scan import scan_file
from scanner.yara_scan import scan_yara
from scanner.risk_score import calculate_risk
from scanner.ai_explain import generate_explanation

from scanner.malware_extractor import extract_malware
from scanner.recursive_scan import scan_extracted_files
from scanner.quarantine import quarantine_file
from scanner.recovery_engine import recover_file



app = FastAPI()



Base.metadata.create_all(
    bind=engine
)



templates = Jinja2Templates(
    directory="templates"
)



UPLOAD_DIR = Path(__file__).parent / "uploads"


UPLOAD_DIR.mkdir(
    exist_ok=True
)



MAX_UPLOAD_SIZE = 100 * 1024 * 1024



scan_status = {

    "state":"idle",

    "result":None

}






def get_current_user(request: Request):

    token = request.cookies.get(
        "token"
    )


    if not token:

        return None


    return decode_token(token)





def is_logged_in(request: Request):

    return get_current_user(request) is not None







@app.get("/", response_class=HTMLResponse)
def home(request: Request):


    return templates.TemplateResponse(

        request=request,

        name="index.html"

    )








@app.get("/progress", response_class=HTMLResponse)
def progress(request: Request):


    return templates.TemplateResponse(

        request=request,

        name="progress.html"

    )








@app.get("/scan-status")
def scan_status_api():


 return scan_status
@app.get("/report", response_class=HTMLResponse)
def report(request: Request):

    result = scan_status.get("result") or {}


    return templates.TemplateResponse(

        request=request,

        name="report.html",

        context={


            "filename":
            result.get(
                "filename",
                "N/A"
            ),


            "size":
            result.get(
                "size",
                0
            ),


            "hash":
            result.get(
                "hash",
                "N/A"
            ),



            "scan":
            result.get(
                "scan",
                {}
            ).get(
                "status",
                "Not scanned"
            ),



            "details":
            result.get(
                "scan",
                {}
            ).get(
                "details",
                ""
            ),



            "yara":
            result.get(
                "yara",
                {}
            ).get(
                "status",
                "Not scanned"
            ),



            "yara_details":
            result.get(
                "yara",
                {}
            ).get(
                "matches",
                ""
            ),



            "risk_score":
            result.get(
                "risk",
                {}
            ).get(
                "score",
                0
            ),



            "risk_level":
            result.get(
                "risk",
                {}
            ).get(
                "level",
                "UNKNOWN"
            ),



            "ai_message":
            result.get(
                "explanation",
                {}
            ).get(
                "message",
                ""
            ),



            "ai_advice":
            result.get(
                "explanation",
                {}
            ).get(
                "advice",
                ""
            ),



            "extracted":
            result.get(
                "extracted",
                []
            )

        }

    )







@app.post("/upload")
async def upload_file(

    request: Request,

    background_tasks: BackgroundTasks,

    file: UploadFile = File(...)

):


    username = get_current_user(
        request
    )



    if not username:


        return RedirectResponse(

            "/login",

            status_code=303

        )




    data = await file.read()



    if not data:


        return HTMLResponse(

            "Empty file uploaded",

            status_code=400

        )





    if len(data) > MAX_UPLOAD_SIZE:


        return HTMLResponse(

            "File too large",

            status_code=400

        )





    safe_name = Path(
        file.filename
    ).name



    file_path = UPLOAD_DIR / safe_name




    with open(

        file_path,

        "wb"

    ) as f:


        f.write(data)





    scan_status["state"] = "running"

    scan_status["result"] = None




    background_tasks.add_task(

        run_scan,

        str(file_path),

        safe_name,

        username

    )




    return RedirectResponse(

        "/progress",

        status_code=303

    )









def run_scan(

    file_path,

    filename,

    username

):


    global scan_status



    try:



        print("1. Scan started")



        file_hash = get_sha256(

            file_path

        )



        file_size = os.path.getsize(

            file_path

        )





        print("2. ClamAV scanning")



        clamav_result = scan_file(

            file_path

        )





        print("3. YARA scanning")



        yara_result = scan_yara(

            file_path

        )





        risk = calculate_risk(

            clamav_result["status"],

            yara_result["status"]

        )





        print("4. Extraction")



        extracted = extract_malware(

            file_path

        )



        recursive = []



        if isinstance(extracted,list):


            valid_files = []



            for item in extracted:


                if os.path.isfile(item):

                    valid_files.append(item)





            if valid_files:


                recursive = scan_extracted_files(

                    valid_files

                )





        explanation = generate_explanation(

            risk["score"],

            risk["level"],

            clamav_result["status"],

            yara_result["status"]

        )



        db = SessionLocal()



        try:



            scan = ScanHistory(

                filename=filename,

                username=username,

                file_hash=file_hash,

                antivirus=clamav_result["status"],

                yara=yara_result["status"],

                risk_score=risk["score"],

                risk_level=risk["level"]

            )


            db.add(scan)

            db.commit()




        finally:

            db.close()




        quarantined = False



        if risk["score"] >= 70:



            quarantine_path = quarantine_file(

                file_path

            )



            quarantined = True



            db = SessionLocal()



            try:


                q = QuarantineFile(


                    filename=filename,


                    username=username,


                    original_path=str(file_path),


                    quarantine_path=str(quarantine_path),


                    reason="High risk malware detected",


                    file_size=file_size,


                    risk_level=risk["level"]

                )



                db.add(q)

                db.commit()



            finally:


                db.close()



            print("FILE QUARANTINED")





        scan_status = {


            "state":"done",


            "result":{


                "filename":filename,


                "size":file_size,


                "hash":file_hash,


                "scan":clamav_result,


                "yara":yara_result,


                "risk":risk,


                "explanation":explanation,


                "extracted":extracted,


                "recursive":recursive,


                "quarantined":quarantined


            }


        }



        print("SCAN COMPLETE")



    except Exception as e:



        print(

            "SCAN ERROR:",

            e

        )



        scan_status = {


            "state":"done",


            "result":{


                "error":str(e)

            }

        }

@app.get(
    "/history",
    response_class=HTMLResponse
)
def history(request: Request):


    username = get_current_user(
        request
    )


    if not username:


        return RedirectResponse(

            "/login",

            status_code=303

        )



    db = SessionLocal()



    try:


        scans = db.query(

            ScanHistory

        ).filter(

            ScanHistory.username == username

        ).order_by(

            ScanHistory.id.desc()

        ).all()



    finally:

        db.close()



    return templates.TemplateResponse(

        request=request,

        name="history.html",

        context={

            "scans":scans

        }

    )


@app.get(
    "/login",
    response_class=HTMLResponse
)
def login_page(request: Request):

    return templates.TemplateResponse(

        request=request,

        name="login.html"

    )





@app.post("/login")
def login_user(

    username: str = Form(...),

    password: str = Form(...)

):


    db = SessionLocal()


    user = db.query(
        User
    ).filter(

        User.username == username

    ).first()



    db.close()



    if not user:

        return HTMLResponse(
            "User not found",
            status_code=404
        )




    if not verify_password(

        password,

        user.password

    ):


        return HTMLResponse(

            "Wrong password",

            status_code=401

        )




    token = create_token(

        username

    )



    response = RedirectResponse(

        "/dashboard",

        status_code=303

    )


    response.set_cookie(

        key="token",

        value=token

    )


    return response



@app.get(
    "/register",
    response_class=HTMLResponse
)
def register_page(request: Request):


    return templates.TemplateResponse(

        request=request,

        name="register.html"

    )





@app.post("/register")
def register_user(

    username:str = Form(...),

    password:str = Form(...)

):


    db = SessionLocal()



    existing = db.query(
        User
    ).filter(

        User.username == username

    ).first()



    if existing:

        db.close()

        return HTMLResponse(
            "User already exists"
        )



    user = User(

        username=username,

        password=hash_password(password)

    )


    db.add(user)

    db.commit()

    db.close()



    return RedirectResponse(

        "/login",

        status_code=303

    )



@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
def dashboard(request: Request):


    username = get_current_user(
        request
    )


    if not username:


        return RedirectResponse(

            "/login",

            status_code=303

        )



    db = SessionLocal()



    try:



        total = db.query(

            ScanHistory

        ).filter(

            ScanHistory.username == username

        ).count()




        safe = db.query(

            ScanHistory

        ).filter(

            ScanHistory.username == username,

            ScanHistory.risk_score == 0

        ).count()




        malware_count = db.query(

            ScanHistory

        ).filter(

            ScanHistory.username == username,

            ScanHistory.risk_score >= 70

        ).count()




        risky = db.query(

            ScanHistory

        ).filter(

            ScanHistory.username == username,

            ScanHistory.risk_score > 0

        ).count()




        quarantined = db.query(

            QuarantineFile

        ).filter(

            QuarantineFile.username == username

        ).count()




        recovered_count = db.query(

            QuarantineFile

        ).filter(

            QuarantineFile.username == username,

            QuarantineFile.reason.like("%Recovered%")

        ).count()




        recent = db.query(

            ScanHistory

        ).filter(

            ScanHistory.username == username

        ).order_by(

            ScanHistory.id.desc()

        ).limit(5).all()




    finally:

        db.close()




    return templates.TemplateResponse(

        request=request,

        name="dashboard.html",

        context={


            "total":total,


            "safe":safe,


            "risky":risky,


            "quarantined":quarantined,


            "malware_count":malware_count,


            "recovered_count":recovered_count,


            "recent":recent

        }

    )









@app.get(
    "/quarantine",
    response_class=HTMLResponse
)
def quarantine_page(request: Request):


    username = get_current_user(
        request
    )



    if not username:


        return RedirectResponse(

            "/login",

            status_code=303

        )



    db = SessionLocal()



    try:


        files = db.query(

            QuarantineFile

        ).filter(

            QuarantineFile.username == username

        ).all()



    finally:

        db.close()




    return templates.TemplateResponse(

        request=request,

        name="quarantine.html",

        context={

            "files":files

        }

    )









@app.get("/delete/{file_id}")
def delete_quarantine_file(

    request: Request,

    file_id:int

):


    username = get_current_user(
        request
    )


    if not username:


        return RedirectResponse(

            "/login",

            status_code=303

        )



    db = SessionLocal()



    try:


        item = db.query(

            QuarantineFile

        ).filter(

            QuarantineFile.id == file_id,

            QuarantineFile.username == username

        ).first()




        if item:



            if os.path.exists(

                item.quarantine_path

            ):


                os.remove(

                    item.quarantine_path

                )



            db.delete(item)

            db.commit()



    finally:


        db.close()



    return RedirectResponse(

        "/quarantine",

        status_code=303

    )









@app.get("/recover/{file_id}")
def recover(

    request:Request,

    file_id:int

):


    username = get_current_user(
        request
    )


    if not username:


        return RedirectResponse(

            "/login",

            status_code=303

        )



    db = SessionLocal()



    try:


        item = db.query(

            QuarantineFile

        ).filter(

            QuarantineFile.id == file_id,

            QuarantineFile.username == username

        ).first()



        if not item:


            return {

                "error":"File not found"

            }



        result = recover_file(

            item.quarantine_path

        )



        if result.get("status") == "success":


            clean_path = result.get(

                "clean_file"

            )


            if clean_path:


                item.reason = (

                    "Recovered - malware removed | "

                    +

                    os.path.basename(clean_path)

                )



                db.commit()





        return templates.TemplateResponse(

            request=request,

            name="recovery_result.html",

            context={


                "result":result,


                "file_id":file_id


            }

        )



    finally:


        db.close()







@app.get("/download/{file_id}")
def download_clean_file(

    request:Request,

    file_id:int

):


    username = get_current_user(
        request
    )


    if not username:


        return RedirectResponse(

            "/login",

            status_code=303

        )



    db = SessionLocal()



    try:


        item = db.query(

            QuarantineFile

        ).filter(

            QuarantineFile.id == file_id,

            QuarantineFile.username == username

        ).first()



        if not item:


            return {

                "error":"File record not found"

            }





        filename = item.reason.split("|")[-1].strip()



        filepath = os.path.join(

            "recovered",

            filename

        )



        if not os.path.exists(filepath):


            return {


                "error":

                "Recovered file missing"

            }




        return FileResponse(

            path=filepath,

            filename=filename,

            media_type="application/zip"

        )



    finally:


        db.close()









@app.get("/logout")
def logout():


    response = RedirectResponse(

        "/login",

        status_code=303

    )


    response.delete_cookie(

        "token"

    )


    return response