import "pe"
import "dotnet"

rule use_win_base_api {

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
        $import1 = "TerminateProcess" wide ascii
        $import2 = "LoadLibraryA" wide ascii
        $import3 = "LoadLibraryExA" wide ascii
        $import4 = "GetDriveTypeA" wide ascii
        $import5 = "GetVolumeInformationA" wide ascii
        $import6 = "GetSystemInfo" wide ascii
        $import7 = "GetStartupInfoA" wide ascii
        $import8 = "GetCommandLineA" wide ascii
        $import9 = "GetCommandLineW" wide ascii
        $import10 = "LoadLibraryExW" wide ascii
        $import11 = "GetDriveTypeW" wide ascii
        $import12 = "GetStartupInfoW" wide ascii
        $import13 = "LoadLibraryW" wide ascii
        $import14 = "GetDiskFreeSpaceW" wide ascii
        $import15 = "GetStartupInfoW" wide ascii
        $import16 = "GetDiskFreeSpaceExW" wide ascii
        $import17 = "FindFirstVolumeW" wide ascii
        $import18 = "FindNextVolumeW" wide ascii
        $import19 = "GetDiskFreeSpaceExA" wide ascii
        $import20 = "GetVolumeInformationByHandleW" wide ascii
        $import21 = "CreateFiberEx" wide ascii

        $golang1 = "syscall.Open" wide ascii

    condition:
        any of them

		or (pe.imports("kernel32.dll", "TerminateProcess")) 
        or (pe.imports("kernel32.dll", "LoadLibraryA"))
        or (pe.imports("kernel32.dll", "LoadLibraryExA"))
        or (pe.imports("kernel32.dll", "GetDriveTypeA")) 
        or (pe.imports("kernel32.dll", "GetVolumeInformationA"))
        or (pe.imports("kernel32.dll", "GetSystemInfo"))
        or (pe.imports("kernel32.dll", "LoadLibraryExW")) 
        or (pe.imports("kernel32.dll", "GetDriveTypeW"))
        or (pe.imports("kernel32.dll", "GetStartupInfoW"))
        or (pe.imports("kernel32.dll", "LoadLibraryW"))
        or (pe.imports("kernel32.dll", "GetDiskFreeSpaceW"))
        or (pe.imports("kernel32.dll", "GetStartupInfoW"))
        or (pe.imports("kernel32.dll", "GetDiskFreeSpaceExW"))
        or (pe.imports("kernel32.dll", "FindFirstVolumeW"))
        or (pe.imports("kernel32.dll", "FindNextVolumeW"))
        or (pe.imports("kernel32.dll", "GetDiskFreeSpaceExA"))
        or (pe.imports("kernel32.dll", "GetVolumeInformationByHandleW"))
        or (pe.imports("kernel32.dll", "CreateFiberEx"))
    
}