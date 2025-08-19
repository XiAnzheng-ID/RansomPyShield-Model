import "pe"
import "dotnet"

rule files_directories_manipulation {

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
        $import1 = "CreateDirectoryA" wide ascii
        $import2 = "CreateFileA" wide ascii
        $import3 = "DeleteFileA" wide ascii
        $import4 = "GetWindowsDirectoryA" wide ascii
        $import5 = "GetSystemDirectoryA" wide ascii
        $import6 = "GetFileAttributesA" wide ascii
        $import7 = "GetFileVersionInfoSizeA" wide ascii
        $import8 = "GetFileVersionInfoA" wide ascii
        $import9 = "FindFirstFileA" wide ascii
        $import10 = "CreateDirectoryW" wide ascii
        $import11 = "CreateFileW" wide ascii
        $import12 = "DeleteFileW" wide ascii
        $import13 = "FindFirstFileW" wide ascii
        $import14 = "RemoveDirectoryW" wide ascii
        $import15 = "SetDllDirectoryW" wide ascii
        $import16 = "GetFileAttributesW" wide ascii
        $import17 = "CopyFileW" wide ascii
        $import18 = "PathRemoveFileSpecW" wide ascii
        $import19 = "NtCreateFile" wide ascii
        $import20 = "NtDeviceIoControlFile" wide ascii
        $import21 = "MoveFileExW" wide ascii
        $import22 = "CreateFileMappingW" wide ascii
        $import23 = "GetWindowsDirectoryW" wide ascii
        $import24 = "SetVolumeMountPointW" wide ascii
        $import25 = "GetVolumePathNamesForVolumeNameW" wide ascii
        $import26 = "CreateFileTransactedA" wide ascii
        $import27 = "CreateHardLinkW" wide ascii
        $import28 = "IcmpCreateFile" wide ascii
        $import29 = "BackupEventLogW" wide ascii

        $golang1 = "io/ioutil" wide ascii
        $golang2 = "os.OpenFile" wide ascii
        $golang3 = "os.openFileNolog" wide ascii
        $golang4 = "os.rename" wide ascii
        $golang5 = "os.newFile" wide ascii
        $golang6 = "os.newFileStatFromGetFileInformationByHandle" wide ascii
        $golang7 = "os.ReadDir" wide ascii
        $golang8 = "os.Remove" wide ascii
        $golang9 = "os.WriteFile" wide ascii
        $golang10 = "os.newFile" wide ascii

    condition:
        any of them

		or (pe.imports("kernel32.dll", "CreateDirectoryA")) 
        or (pe.imports("kernel32.dll", "CreateFileA"))
        or (pe.imports("kernel32.dll", "DeleteFileA"))
        or (pe.imports("kernel32.dll", "GetWindowsDirectoryA")) 
        or (pe.imports("kernel32.dll", "GetSystemDirectoryA"))
        or (pe.imports("kernel32.dll", "GetFileAttributesA"))
        or (pe.imports("kernel32.dll", "FindFirstFileA"))
        or (pe.imports("kernel32.dll", "CreateDirectoryW"))
        or (pe.imports("kernel32.dll", "CreateFileW"))
        or (pe.imports("kernel32.dll", "DeleteFileW")) 
        or (pe.imports("kernel32.dll", "FindFirstFileW"))
        or (pe.imports("kernel32.dll", "RemoveDirectoryW"))
        or (pe.imports("kernel32.dll", "GetFileAttributesW"))
        or (pe.imports("kernel32.dll", "SetDllDirectoryW"))
        or (pe.imports("kernel32.dll", "CopyFileW"))
        or (pe.imports("kernel32.dll", "MoveFileExW"))
        or (pe.imports("kernel32.dll", "CreateFileMappingW"))
        or (pe.imports("kernel32.dll", "GetWindowsDirectoryW"))
        or (pe.imports("kernel32.dll", "SetVolumeMountPointW"))
        or (pe.imports("kernel32.dll", "GetVolumePathNamesForVolumeNameW"))
        or (pe.imports("kernel32.dll", "CreateFileTransactedA"))
        or (pe.imports("kernel32.dll", "CreateHardLinkW"))

        or (pe.imports("version.dll", "GetFileVersionInfoSizeA"))
        or (pe.imports("version.dll", "GetFileVersionInfoA"))

        or (pe.imports("shlwapi.dll", "PathRemoveFileSpecW"))

        or (pe.imports("ntdll.dll", "NtCreateFile"))
        or (pe.imports("ntdll.dll", "NtDeviceIoControlFile"))

        or (pe.imports("iphlpapi.dll", "IcmpCreateFile"))

        or (pe.imports("advapi.dll", "BackupEventLogW"))
}