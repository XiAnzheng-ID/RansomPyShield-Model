import "pe"
import "dotnet"

rule retrieves_account_information {

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
        $import1 = "LookupPrivilegeValueA" wide ascii
        $import2 = "LookupPrivilegeValueW" wide ascii
        $import3 = "LogonUserA" wide ascii
        $import4 = "GetComputerNameA" wide ascii
        $import5 = "GetUserNameA" wide ascii
        $import6 = "LogonUserW" wide ascii
        $import7 = "QueryDosDeviceA" wide ascii

    condition:
        any of them

		or (pe.imports("advapi32.dll", "LookupPrivilegeValueA"))
        or (pe.imports("advapi32.dll", "LookupPrivilegeValueW")) 
        or (pe.imports("advapi32.dll", "LogonUserA"))
        or (pe.imports("advapi32.dll", "GetUserNameA")) 
        or (pe.imports("advapi32.dll", "LogonUserW")) 

        or (pe.imports("kernel32.dll", "GetComputerNameA"))
        or (pe.imports("kernel32.dll", "QueryDosDeviceA"))
}