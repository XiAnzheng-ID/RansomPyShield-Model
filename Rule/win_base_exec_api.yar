import "pe"
import "dotnet"

rule can_execute_other_programs {

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
        $import1 = "WriteConsoleA" wide ascii
        $import2 = "WriteConsoleW" wide ascii
        $import3 = "PeekConsoleInputA" wide ascii
        $import4 = "ReadConsoleInputA" wide ascii
        $import5 = "SetConsoleCtrlHandler" wide ascii
        $import6 = "SetConsoleMode" wide ascii
        $import7 = "ReadConsoleW" wide ascii
        $import8 = "SetStdHandle" wide ascii
        $import9 = "GetConsoleWindow" wide ascii
        $import10 = "GetConsoleMode" wide ascii
        $import11 = "GetConsoleOutputCP" wide ascii
        $import12 = "GenerateConsoleCtrlEvent" wide ascii
        $import13 = "GetConsoleScreenBufferInfo" wide ascii
        $import14 = "SetConsoleTextAttribute" wide ascii
        $import15 = "WinExec" wide ascii
        $import16 = "AssignProcessToJobObject" wide ascii
        $import17 = "ReadConsoleA" wide ascii
        $import18 = "GetConsoleInputExeNameW" wide ascii
        $import19 = "AllocConsole" wide ascii
        $import20 = "AttachConsole" wide ascii
        $import21 = "GetConsoleCP" wide ascii

        $import22 = "_get_narrow_winmain_command_line" wide ascii

        $golang1 = "os.StartProcess" wide ascii
        $golang2 = "os/exec" wide ascii
        $golang3 = "syscall.StartProcess" wide ascii
        $golang4 = "os.Kill" wide ascii

    condition:
        any of them

		or (pe.imports("kernel32.dll", "WriteConsoleA")) 
        or (pe.imports("kernel32.dll", "WriteConsoleW"))
        or (pe.imports("kernel32.dll", "PeekConsoleInputA"))
        or (pe.imports("kernel32.dll", "ReadConsoleInputA")) 
        or (pe.imports("kernel32.dll", "SetConsoleCtrlHandler"))
        or (pe.imports("kernel32.dll", "SetConsoleMode"))
        or (pe.imports("kernel32.dll", "ReadConsoleW"))
        or (pe.imports("kernel32.dll", "SetStdHandle"))
        or (pe.imports("kernel32.dll", "GetConsoleWindow")) 
        or (pe.imports("kernel32.dll", "GetConsoleMode"))
        or (pe.imports("kernel32.dll", "GetConsoleOutputCP"))
        or (pe.imports("kernel32.dll", "GenerateConsoleCtrlEvent"))
        or (pe.imports("kernel32.dll", "SetConsoleTextAttribute"))
        or (pe.imports("kernel32.dll", "GetConsoleScreenBufferInfo"))
        or (pe.imports("kernel32.dll", "WinExec"))
        or (pe.imports("kernel32.dll", "AssignProcessToJobObject"))
        or (pe.imports("kernel32.dll", "ReadConsoleA"))
        or (pe.imports("kernel32.dll", "GetConsoleInputExeNameW"))
        or (pe.imports("kernel32.dll", "AllocConsole"))
        or (pe.imports("kernel32.dll", "AttachConsole"))
        or (pe.imports("kernel32.dll", "GetConsoleCP"))

        or (pe.imports("api-ms-win-crt-runtime-l1-1-0.dll", "_get_narrow_winmain_command_line"))
    
}