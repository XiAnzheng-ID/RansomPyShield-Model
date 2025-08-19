import "pe"
import "dotnet"

rule performs_gui_actions {

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
        $import1 = "FindWindowW" wide ascii
        $import2 = "PeekMessageA" wide ascii
        $import3 = "PeekMessageW" wide ascii
        $import4 = "CreateWindowExW" wide ascii
        $import5 = "CreateWindowExA" wide ascii
        $import6 = "EmptyClipboard" wide ascii
        $import7 = "OpenClipboard" wide ascii

    condition:
        any of them

		or (pe.imports("user32.dll", "PeekMessageA"))
        or (pe.imports("user32.dll", "PeekMessageW")) 
        or (pe.imports("user32.dll", "CreateWindowExW"))
        or (pe.imports("user32.dll", "CreateWindowExA"))
        or (pe.imports("user32.dll", "EmptyClipboard"))
        or (pe.imports("user32.dll", "OpenClipboard")) 
    
}