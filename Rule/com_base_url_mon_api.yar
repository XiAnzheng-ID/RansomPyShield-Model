import "pe"
import "dotnet"

rule can_download_execute_components {

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
        $import1 = "CreateStreamOnHGlobal" wide ascii
        $import2 = "CoCreateInstance" wide ascii
        $import3 = "URLDownloadToFileA" wide ascii
        $import4 = "CoInitializeSecurity" wide ascii

    condition:
        any of them
        
		or (pe.imports("ole32.dll", "CreateStreamOnHGlobal"))
        or (pe.imports("ole32.dll", "CoCreateInstance")) 

        or (pe.imports("urlmon.dll", "URLDownloadToFileA")) 
    
}