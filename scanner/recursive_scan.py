import os

from scanner.hash_scan import get_sha256
from scanner.clamav_scan import scan_file
from scanner.yara_scan import scan_yara
from scanner.risk_score import calculate_risk



MAX_EXTRACTED_FILES = 50



def scan_extracted_files(files):

    results = []


    for index, file_path in enumerate(files):


        if index >= MAX_EXTRACTED_FILES:

            results.append({

                "filename": "scan_limit",

                "error": 
                "Maximum extracted file limit reached"

            })

            break



        try:


            if not os.path.isfile(file_path):

                continue



            file_hash = get_sha256(
                file_path
            )


            clamav_result = scan_file(
                file_path
            )


            yara_result = scan_yara(
                file_path
            )


            risk = calculate_risk(

                clamav_result["status"],

                yara_result["status"]

            )



            results.append({

                "filename":
                os.path.basename(file_path),


                "hash":
                file_hash,


                "clamav":
                clamav_result,


                "yara":
                yara_result,


                "risk":
                risk

            })



        except Exception as e:


            results.append({

                "filename":
                os.path.basename(file_path),


                "error":
                str(e)

            })


    return results