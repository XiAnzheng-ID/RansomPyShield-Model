import "pe"
import "dotnet"

rule can_manipulate_windows_services {

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
        $import1 = "ControlService" wide ascii
        $import2 = "CreateServiceA" wide ascii
        $import3 = "OpenSCManagerA" wide ascii
        $import4 = "OpenServiceA" wide ascii
        $import5 = "QueryServiceStatus" wide ascii
        $import6 = "StartServiceA" wide ascii
        $import7 = "OpenSCManagerW" wide ascii
        $import8 = "OpenServiceW" wide ascii
        $import9 = "EnumDependentServicesW" wide ascii
        $import10 = "QueryServiceStatusEx" wide ascii
        $import11 = "EnumDependentServicesA" wide ascii
        $import12 = "StartServiceW" wide ascii

    condition:
        any of them

		or (pe.imports("advapi32.dll", "ControlService"))
        or (pe.imports("advapi32.dll", "CreateServiceA"))
        or (pe.imports("advapi32.dll", "OpenSCManagerA"))
        or (pe.imports("advapi32.dll", "OpenServiceA"))
        or (pe.imports("advapi32.dll", "QueryServiceStatus"))
        or (pe.imports("advapi32.dll", "StartServiceA"))
        or (pe.imports("advapi32.dll", "OpenSCManagerW"))
        or (pe.imports("advapi32.dll", "OpenServiceW"))
        or (pe.imports("advapi32.dll", "EnumDependentServicesW"))
        or (pe.imports("advapi32.dll", "QueryServiceStatusEx"))
        or (pe.imports("advapi32.dll", "EnumDependentServicesA"))
        or (pe.imports("advapi32.dll", "StartServiceW"))
    
}