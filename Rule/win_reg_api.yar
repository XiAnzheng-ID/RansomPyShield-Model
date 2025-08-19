import "pe"
import "dotnet"

rule can_manipulate_windows_registry {

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
        $import1 = "RegCreateKeyExA" wide ascii
        $import2 = "RegOpenKeyExA" wide ascii
        $import3 = "RegQueryInfoKeyA" wide ascii
        $import4 = "RegQueryValueExA" wide ascii
        $import5 = "RegSetValueExA" wide ascii
        $import6 = "RegConnectRegistryA" wide ascii
        $import7 = "RegCreateKeyA" wide ascii
        $import8 = "RegOpenKeyExW" wide ascii
        $import9 = "RegQueryValueExW" wide ascii
        $import10 = "RegCreateKeyExW" wide ascii
        $import11 = "RegSetValueExW" wide ascii
        $import12 = "RegGetValueW" wide ascii
        $import13 = "RegCreateKeyW" wide ascii

    condition:
        any of them

		or (pe.imports("advapi32.dll", "RegCreateKeyExA"))
        or (pe.imports("advapi32.dll", "RegOpenKeyExA")) 
        or (pe.imports("advapi32.dll", "RegQueryInfoKeyA")) 
        or (pe.imports("advapi32.dll", "RegQueryValueExA")) 
        or (pe.imports("advapi32.dll", "RegSetValueExA"))
        or (pe.imports("advapi32.dll", "RegConnectRegistryA")) 
        or (pe.imports("advapi32.dll", "RegCreateKeyA"))
        or (pe.imports("advapi32.dll", "RegOpenKeyExW")) 
        or (pe.imports("advapi32.dll", "RegQueryValueExW"))
        or (pe.imports("advapi32.dll", "RegCreateKeyExW")) 
        or (pe.imports("advapi32.dll", "RegSetValueExW"))
        or (pe.imports("advapi32.dll", "RegGetValueW"))
        or (pe.imports("advapi32.dll", "RegCreateKeyW"))
    
}