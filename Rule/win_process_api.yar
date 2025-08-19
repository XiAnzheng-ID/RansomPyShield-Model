import "pe"
import "dotnet"

rule can_create_process_and_threads {

    meta:
        author = "XiAnzheng"
        source_url = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware"
        description = "Check for Import combination (can create FP)"
        date = "2024-11-07"
        updated = "2024-11-20"
        yarahub_license = "CC0 1.0"
        yarahub_uuid = "3295ce35-cb35-4203-bb37-7503ddf111c5"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "16f76e17d64f5ee805031ddf9f862f59"

    strings:
        $import1 = "CreateProcessA" wide ascii
        $import2 = "OpenProcessToken" wide ascii
        $import3 = "CloseHandle" wide ascii
        $import4 = "CreateThread" wide ascii
        $import5 = "OpenProcess" wide ascii
        $import6 = "CreateProcessW" wide ascii
        $import7 = "InternetCloseHandle" wide ascii
        $import8 = "WinHttpCloseHandle" wide ascii
        $import9 = "SetProcessShutdownParameters" wide ascii
        $import10 = "CreateProcessInternalW" wide ascii
        $import11 = "SetThreadToken" wide ascii
        $import12 = "IcmpCloseHandle" wide ascii

    condition:
        any of them

		or (pe.imports("kernel32.dll", "OpenProcess")) 
        or (pe.imports("kernel32.dll", "CreateProcessA")) 
        or (pe.imports("kernel32.dll", "CloseHandle"))
        or (pe.imports("kernel32.dll", "CreateThread"))
        or (pe.imports("kernel32.dll", "CreateProcessW"))
        or (pe.imports("kernel32.dll", "SetProcessShutdownParameters"))
        or (pe.imports("kernel32.dll", "CreateProcessInternalW"))

        or (pe.imports("advapi32.dll", "OpenProcessToken"))
        or (pe.imports("advapi32.dll", "SetThreadToken"))

        or (pe.imports("wininet.dll", "InternetCloseHandle"))

        or (pe.imports("winhttp.dll", "WinHttpCloseHandle"))

        or (pe.imports("iphlpapi.dll", "IcmpCloseHandle"))
    
}