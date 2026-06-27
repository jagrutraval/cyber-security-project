import os
import shutil
import uuid


QUARANTINE_FOLDER = "quarantine"


os.makedirs(
    QUARANTINE_FOLDER,
    exist_ok=True
)



def quarantine_file(file_path: str):


    if not os.path.exists(file_path):

        return None



    filename = os.path.basename(
        file_path
    )


    unique_name = (
        str(uuid.uuid4())
        + "_"
        + filename
    )


    quarantine_path = os.path.join(

        QUARANTINE_FOLDER,

        unique_name

    )


    try:


        shutil.move(

            file_path,

            quarantine_path

        )


        return quarantine_path



    except Exception:

        return None