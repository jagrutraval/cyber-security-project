import os
import yara


RULE_PATH = "yara_rules/basic_rules.yar"


_rules = None



def load_rules():

    global _rules


    if _rules is not None:
        return _rules


    if not os.path.exists(RULE_PATH):

        return None


    try:

        _rules = yara.compile(
            filepath=RULE_PATH
        )

        return _rules


    except Exception:

        return None




def scan_yara(file_path: str):

    rules = load_rules()


    if rules is None:

        return {

            "status": "YARA Not Available",

            "matches": "Rule file not found"

        }


    if not os.path.exists(file_path):

        return {

            "status": "Error",

            "matches": "File not found"

        }


    try:

        matches = rules.match(
            file_path,
            timeout=30
        )


        if matches:

            return {

                "status": "Suspicious",

                "matches": str(matches)

            }


        return {

            "status": "No YARA Match",

            "matches": "No rules matched"

        }



    except yara.TimeoutError:

        return {

            "status": "YARA Timeout",

            "matches": "Scan exceeded time limit"

        }



    except Exception as e:

        return {

            "status": "Error",

            "matches": str(e)

        }