import "pe"
import "dotnet"

rule use_security_base_api {

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
        $import1 = "AdjustTokenPrivileges" wide ascii
        $import2 = "GetTokenInformation" wide ascii
        $import3 = "ImpersonateLoggedOnUser" wide ascii
        $import4 = "CheckTokenMembership" wide ascii
        $import5 = "DuplicateToken" wide ascii
        $import6 = "AddAccessDeniedAce" wide ascii

    condition:
        any of them
        
		or (pe.imports("advapi32.dll", "AdjustTokenPrivileges")) 
        or (pe.imports("advapi32.dll", "GetTokenInformation"))
        or (pe.imports("advapi32.dll", "ImpersonateLoggedOnUser"))
        or (pe.imports("advapi32.dll", "CheckTokenMembership"))
        or (pe.imports("advapi32.dll", "DuplicateToken"))
        or (pe.imports("advapi32.dll", "AddAccessDeniedAce"))
    
}