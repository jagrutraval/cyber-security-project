import os
import zipfile
import shutil
import uuid


from scanner import yara_scan
from scanner import clamav_scan


RECOVERED_FOLDER = "recovered"
TEMP_FOLDER = "temp_recovery"



def recover_file(file_path):

    try:

        if file_path.lower().endswith(".zip"):

            return clean_zip(file_path)


        return {

            "status": "failed",
            "message": "Only ZIP recovery supported",
            "removed_files": [],
            "clean_file": None

        }



    except Exception as e:


        return {

            "status": "error",
            "message": str(e),
            "removed_files": [],
            "clean_file": None

        }





def clean_zip(file_path):


    removed_files = []

    scan_report = []



    # reset temp folder

    if os.path.exists(TEMP_FOLDER):

        shutil.rmtree(TEMP_FOLDER)



    os.makedirs(
        TEMP_FOLDER,
        exist_ok=True
    )


    os.makedirs(
        RECOVERED_FOLDER,
        exist_ok=True
    )



    # Extract zip

    with zipfile.ZipFile(file_path,"r") as z:


        z.extractall(
            TEMP_FOLDER
        )





    # Scan files

    for root,dirs,files in os.walk(TEMP_FOLDER):


        for file in files:


            full_path = os.path.join(
                root,
                file
            )


            yara_detected = False

            clam_detected = False



            try:

                yara_detected = yara_scan.scan_file(
                    full_path
                )

            except Exception:

                pass




            try:

                clam_detected = clamav_scan.scan_file(
                    full_path
                )

            except Exception:

                pass





            if yara_detected or clam_detected:


                removed_files.append(file)



                scan_report.append({

                    "file":file,

                    "yara":yara_detected,

                    "clamav":clam_detected,

                    "action":"removed"

                })



                try:

                    os.remove(full_path)

                except FileNotFoundError:

                    pass





    # create clean zip


    clean_filename = (
        str(uuid.uuid4())
        +
        "_clean.zip"
    )



    clean_path = os.path.join(

        RECOVERED_FOLDER,

        clean_filename

    )




    with zipfile.ZipFile(
        clean_path,
        "w"
    ) as output:


        for root,dirs,files in os.walk(TEMP_FOLDER):


            for file in files:


                file_path_inside = os.path.join(
                    root,
                    file
                )


                archive_name = os.path.relpath(

                    file_path_inside,

                    TEMP_FOLDER

                )



                output.write(

                    file_path_inside,

                    archive_name

                )





    # remove temp files

    try:

        shutil.rmtree(TEMP_FOLDER)

    except Exception:

        pass





    return {


        "status":"success",


        "removed_files":removed_files,


        "scan_report":scan_report,


        "clean_file":clean_filename,


        "download_url":"/download/"+clean_filename


    }