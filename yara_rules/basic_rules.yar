rule Suspicious_PowerShell
{

    strings:

        $powershell = "powershell"
        $cmd = "cmd.exe"


    condition:

        any of them
}