rule Sus_CMD_Powershell_Usage
{
    meta:
        author = "XiAnzheng"
        source_url = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware"
        description = "May Contain(Obfuscated or no) Powershell or CMD Command that can be abused by threat actor(can create FP)"
        date = "2025-06-01"
        updated = "2025-06-01"
        yarahub_license = "CC0 1.0"
        yarahub_uuid = "68ec99c5-f2a0-4da7-93d9-58bf7cec9880"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "aa00661ab05eddcb50573492e722f1c8"

    strings:
        //Powershell Usage
        $ps1 = "-ExecutionPolicy Bypass" ascii wide nocase
        $ps2 = "-Ex Bypass" ascii wide nocase
        $ps3 = "Invoke-Expression" ascii wide nocase
        $ps4 = "IEX " ascii wide nocase
        $ps5 = ");IEX " ascii wide nocase
        $ps6 = "IEX;" ascii wide nocase
        $ps7 = "FromBase64String" ascii wide nocase

        //Possibly Encoded/Obfuscated command
        $obf1 = /-join\s*/ ascii wide nocase
        $obf2 = /-nop\s*/ ascii wide nocase
        $obf3 = /-replace\s*/ ascii wide nocase
        $obf4 = /\[char\]\d+/ ascii wide nocase  
        $obf5 = /fromcharcode/ ascii wide nocase
        $obf8 = /[a-z]{3,10}\:\/\/[a-z0-9\.\/\=\%\:\_]{30,}/ ascii wide nocase

        //Windef
        $def1= "MpPreference" ascii wide nocase
        $def2= "Set-MpPreference" ascii wide nocase
        $def3= "Add-MpPreference" ascii wide nocase
        $def4= "WinDefend" ascii wide nocase
        $def5= "Defender" ascii wide nocase
        $def6= "MpCmdRun" ascii wide nocase
        $def7= "MpCmdRun.exe" ascii wide nocase
        $def8= "SECURITY CENTER" ascii wide nocase
        $def9= "Windows Security" ascii wide nocase
        $def10= "Quarantine" ascii wide nocase
        $def11 = /amsiutils|amsiscanbuffer/i ascii wide nocase

        //Utility Abuse
        $util1 = "vssadmin delete shadows" ascii wide nocase
        $util2 = "bcdedit /set" ascii wide nocase
        $util3 = "wbadmin delete catalog" ascii wide nocase
        $util4 = "wmic shadowcopy delete" ascii wide nocase
        $util5 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr" ascii wide nocase
        $util6 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableCMD" ascii wide nocase
        $util7 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableRegistryTools" ascii wide nocase
        $util8 = "taskkill /f" ascii wide nocase
        $util9 = "explorer.exe" ascii wide nocase
        $util10 = "rundll32" ascii wide nocase
        $util11 = /(exe\.|\.exe)[a-z]{5,10}\./ ascii wide nocase
        $util12 = /exe\.[a-z]{6,10}/ ascii wide nocase
        $util13 = /\[reflection\.assembly\]::load\s*/ ascii wide nocase
        $util14 = /start-process\s*-windowstyle\s*hidden/ ascii wide nocase

        // Probably a Downloader
        $powershell1 = "Powershell" ascii wide nocase
        $powershell2 = "Powershell.exe" ascii wide nocase
        $download1 = "New-Object Net.WebClient" ascii wide nocase
        $download2 = "Invoke-WebRequest" ascii wide nocase
        $download3 = "DownloadString" ascii wide nocase
        $download4 = "DownloadFile" ascii wide nocase

        //Contain Python Execution????
        $py1 = /https?:\/\/www\.python\.org\/ftp\/python\/[^\s]+/ ascii wide nocase
        $py2 = /https?:\/\/[^\s]+\.py(\?[^\s]*)?[\s]?/ ascii wide nocase

        //Reversed Command or Script
        $rev3 = "ptth" ascii wide nocase
        $rev4 = "ptths" ascii wide nocase
        $rev5 = "irU-" ascii wide nocase
        $rev6 = "dnammoC-" ascii wide nocase
        $rev7 = "ssapyb ycilopnoitucexe-" ascii wide nocase
        $rev8 = "llehsrewop" ascii wide nocase
        $rev9 = "exe.llehsrewop" ascii wide nocase
        $rev10 = /\[array\]::reverse\(\$\w+\)/ ascii wide nocase

    condition:
        (any of ($obf*) or any of ($ps*) or any of ($rev*) or any of ($py*))
        or ((any of ($powershell*) and any of ($download*)))
        or (2 of ($def*))
        or (2 of ($util*))
}