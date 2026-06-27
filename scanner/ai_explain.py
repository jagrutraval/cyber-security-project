def generate_explanation(
    risk_score,
    risk_level,
    antivirus,
    yara
):


    if risk_level == "SAFE":

        message = (
            f"Risk Score: {risk_score}. "
            "No malware signatures were detected."
            f" Antivirus: {antivirus}. "
            f"YARA: {yara}."
        )


        advice = (
            "File appears safe, "
            "but always verify the source before opening."
        )



    elif risk_level == "MEDIUM RISK":

        message = (
            f"Risk Score: {risk_score}. "
            "Suspicious indicators were found."
            f" Antivirus: {antivirus}. "
            f"YARA: {yara}."
        )


        advice = (
            "Avoid executing the file. "
            "Analyze it in a sandbox environment first."
        )



    elif risk_level == "HIGH RISK":

        message = (
            f"Risk Score: {risk_score}. "
            "Strong malware indicators detected."
            f" Antivirus: {antivirus}. "
            f"YARA: {yara}."
        )


        advice = (
            "Quarantine or delete the file immediately."
        )



    else:

        message = (
            f"Risk Score: {risk_score}. "
            "Unable to determine exact threat level."
        )


        advice = (
            "Perform additional security checks."
        )



    return {

        "message": message,

        "advice": advice

    }