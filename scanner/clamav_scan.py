import subprocess
import os


CLAMAV_PATH = r"C:\Program Files\ClamAV\clamscan.exe"



def scan_file(file_path):


    if not os.path.exists(CLAMAV_PATH):

        return {

            "status": "Scanner Not Installed",

            "details": "ClamAV executable not found"

        }



    try:


        result = subprocess.run(

            [
                CLAMAV_PATH,

                "--no-summary",

                file_path

            ],


            capture_output=True,

            text=True,

            timeout=60

        )



        output = (
            result.stdout
            +
            result.stderr
        )



        if "FOUND" in output:


            return {

                "status": "Malware Detected",

                "details": output

            }



        if result.returncode == 0:


            return {

                "status": "Clean",

                "details": output

            }



        return {

            "status": "Scanner Error",

            "details": output

        }




    except subprocess.TimeoutExpired:


        return {


            "status": "Scanner Timeout",

            "details":
            "ClamAV scan exceeded 60 seconds"

        }



    except Exception as e:


        return {


            "status": "Scanner Error",

            "details": str(e)

        }