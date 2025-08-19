import "pe"
import "dotnet"

rule manipulate_user_auth {

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
        $import1 = "AllocateAndInitializeSid" wide ascii
        $import2 = "EqualSid" wide ascii
        $import3 = "FreeSid" wide ascii
        $import4 = "RevertToSelf" wide ascii
        $import5 = "ConvertSidToStringSidW" wide ascii
        $import6 = "ConvertStringSecurityDescriptorToSecurityDescriptorW" wide ascii
        $import7 = "SetEntriesInAclW" wide ascii
        $import8 = "SetNamedSecurityInfoW" wide ascii
        $import9 = "InitializeSecurityDescriptor" wide ascii

    condition:
        any of them
        
		or (pe.imports("advapi32.dll", "AllocateAndInitializeSid")) 
        or (pe.imports("advapi32.dll", "EqualSid"))
        or (pe.imports("advapi32.dll", "FreeSid"))
        or (pe.imports("advapi32.dll", "RevertToSelf"))
        or (pe.imports("advapi32.dll", "ConvertSidToStringSidW"))
        or (pe.imports("advapi32.dll", "ConvertStringSecurityDescriptorToSecurityDescriptorW"))
        or (pe.imports("advapi32.dll", "SetEntriesInAclW"))
        or (pe.imports("advapi32.dll", "SetNamedSecurityInfoW"))
        or (pe.imports("advapi32.dll", "InitializeSecurityDescriptor"))
    
}