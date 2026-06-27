def calculate_risk(clam_status, yara_status):


    score = 0



    if clam_status == "Malware Detected":

        score += 80



    if clam_status in [
        "Scanner Timeout",
        "Scanner Error"
    ]:

        score += 20



    if yara_status == "Suspicious":

        score += 40



    if score >= 80:

        level = "HIGH RISK"



    elif score >= 40:

        level = "MEDIUM RISK"



    else:

        level = "SAFE"



    return {


        "score": score,

        "level": level

    }