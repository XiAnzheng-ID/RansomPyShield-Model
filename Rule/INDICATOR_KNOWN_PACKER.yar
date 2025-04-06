import "pe"

rule INDICATOR_EXE_Packed_ConfuserEx {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Mod"
        snort2_sid = "930016-930018"
        snort3_sid = "930005-930006"
    strings:
        $s1 = "ConfuserEx " ascii
        $s2 = "ConfusedByAttribute" fullword ascii
        $c1 = "Confuser.Core " ascii wide
        $u1 = "Confu v" fullword ascii
        $u2 = "ConfuByAttribute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($c*) or all of ($u*))
}

rule INDICATOR_EXE_Packed_ConfuserEx_Custom {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Custom; outside of GIT"
    strings:
        $s1 = { 43 6f 6e 66 75 73 65 72 45 78 20 76 [1-2] 2e [1-2] 2e [1-2] 2d 63 75 73 74 6f 6d }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_ConfuserExMod_BedsProtector {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Mod Beds Protector"
        snort2_sid = "930019-930024"
        snort3_sid = "930007-930008"
    strings:
        $s1 = "Beds Protector v" ascii
        $s2 = "Beds-Protector-v" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_ConfuserExMod_Trinity {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Mod Trinity Protector"
        snort2_sid = "930025-930030"
        snort3_sid = "930009-930010"
    strings:
        $s1 = "Trinity0-protecor|" ascii
        $s2 = "#TrinityProtector" fullword ascii
        $s3 = /Trinity\d-protector\|/ ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_PS2EXE {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with PS2EXE"
        snort2_sid = "930004-930006"
        snort3_sid = "930001"
    strings:
        $s1 = "PS2EXE" fullword ascii
        $s2 = "PS2EXEApp" fullword ascii
        $s3 = "PS2EXEHost" fullword ascii
        $s4 = "PS2EXEHostUI" fullword ascii
        $s5 = "PS2EXEHostRawUI" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_LSD {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with LSD packer"
        snort2_sid = "930058-930060"
        snort3_sid = "930021"
    strings:
        $s1 = "This file is packed with the LSD executable packer" ascii
        $s2 = "http://lsd.dg.com" ascii
        $s3 = "&V0LSD!$" fullword ascii
    condition:
         (uint16(0) == 0x5a4d or uint16(0)== 0x457f) and 1 of them
}

rule INDICATOR_EXE_Packed_AspireCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with AspireCrypt"
        snort2_sid = "930013-930015"
        snort3_sid = "930004"
    strings:
        $s1 = "AspireCrypt" fullword ascii
        $s2 = "aspirecrypt.net" ascii
        $s3 = "protected by AspireCrypt" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Spices {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with 9Rays.Net Spices.Net Obfuscator."
        snort2_sid = "930001-930003"
        snort3_sid = "930000"
    strings:
        $s1 = "9Rays.Net Spices.Net" ascii
        $s2 = "protected by 9Rays.Net Spices.Net Obfuscator" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_JAVA_Packed_Allatori {
    meta:
        author = "ditekSHen"
        description = "Detects files packed with Allatori Java Obfuscator"
    strings:
        $s1 = "# Obfuscation by Allatori Obfuscator" ascii wide
    condition:
        all of them
}

rule INDICATOR_EXE_Packed_ASPack {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ASPack"
        snort2_sid = "930007-930009"
        snort3_sid = "930002"
    //strings:
    //    $s1 = { 00 00 ?? 2E 61 73 70 61 63 6B 00 00 }
    condition:
        uint16(0) == 0x5a4d and //all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".aspack"
            )
        )
}

rule INDICATOR_EXE_Packed_Titan {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Titan"
        snort2_sid = "930010-930012"
        snort3_sid = "930003"
    strings:
        $s1 = { 00 00 ?? 2e 74 69 74 61 6e 00 00 }
    condition:
        uint16(0) == 0x5a4d and all of them or 
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".titan"
            )
        )
}

rule INDICATOR_EXE_Packed_aPLib {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with aPLib."
    strings:
        $header = { 41 50 33 32 18 00 00 00 [0-35] 4D 38 5A 90 }
    condition:
        ((uint32(0) == 0x32335041 and uint32(24) == 0x905a384d) or (uint16(0) == 0x5a4d and $header ))
}

rule INDICATOR_EXE_Packed_LibZ {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with LibZ"
        snort2_sid = "930055-930057"
        snort3_sid = "930019-930020"
    strings:
        $s1 = "LibZ.Injected" fullword ascii
        $s2 = "{0:N}.dll" fullword wide
        $s3 = "asmz://(?<guid>[0-9a-fA-F]{32})/(?<size>[0-9]+)(/(?<flags>[a-zA-Z0-9]*))?" fullword wide
        $s4 = "Software\\Softpark\\LibZ" fullword wide
        $s5 = "(AsmZ/{" wide
        $s6 = "asmz://" ascii
        $s7 = "GetRegistryDWORD" ascii
        $s8 = "REGISTRY_KEY_NAME" fullword ascii
        $s9 = "REGISTRY_KEY_PATH" fullword ascii
        $s10 = "InitializeDecoders" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_EXE_Packed_Enigma {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Enigma"
        snort2_sid = "930052-930054"
        snort3_sid = "930018"
    strings:
        $s1 = ".enigma0" fullword ascii
        $s2 = ".enigma1" fullword ascii
        $s3 = ".enigma2" fullword ascii
        $s4 = ".enigma3" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".enigma0" or
                pe.sections[i].name == ".enigma1" or
                pe.sections[i].name == ".enigma2" or
                pe.sections[i].name == ".enigma3"
            )
        )
}

rule INDICATOR_EXE_Python_Byte_Compiled {
    meta:
        author = "ditekSHen"
        description = "Detects python-byte compiled executables"
    strings:
        $s1 = "b64decode" ascii
        $s2 = "decompress" ascii
    condition:
        uint32(0) == 0x0a0df303 and filesize < 5KB and all of them
}

rule INDICATOR_MSI_EXE2MSI {
    meta:
        author = "ditekSHen"
        description = "Detects executables converted to .MSI packages using a free online converter."
        snort2_sid = "930061-930063"
        snort3_sid = "930022"
    strings:
        $winin = "Windows Installer" ascii
        $title = "Exe to msi converter free" ascii
    condition:
        uint32(0) == 0xe011cfd0 and ($winin and $title)
}

rule INDICATOR_EXE_Packed_MPress {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with MPress PE compressor"
        snort2_sid = "930031-930033"
        snort3_sid = "930011"
    strings:
        $s1 = ".MPRESS1" fullword ascii
        $s2 = ".MPRESS2" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them or
         for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".MPRESS1" or
                pe.sections[i].name == ".MPRESS2"
            )
        )
}

rule INDICATOR_EXE_Packed_Nate {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with Nate packer"
        snort2_sid = "930034-930036"
        snort3_sid = "930012"
    strings:
        $s1 = "@.nate0" fullword ascii
        $s2 = "`.nate1" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them or
         for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".nate0" or
                pe.sections[i].name == ".nate1"
            )
        )
}

rule INDICATOR_EXE_Packed_VMProtect {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with VMProtect."
        snort2_sid = "930049-930051"
        snort3_sid = "930017"
    strings:
        $s1 = ".vmp0" fullword ascii
        $s2 = ".vmp1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".vmp0" or
                pe.sections[i].name == ".vmp1"
            )
        )
}

rule INDICATOR_EXE_DotNET_Encrypted {
    meta:
        author = "ditekSHen"
        description = "Detects encrypted or obfuscated .NET executables"
    strings:
        $s1 = "FromBase64String" fullword ascii
        $s2 = "ToCharArray" fullword ascii
        $s3 = "ReadBytes" fullword ascii
        $s4 = "add_AssemblyResolve" fullword ascii
        $s5 = "MemoryStream" fullword ascii
        $s6 = "CreateDecryptor" fullword ascii

         // 08 00 00 00 00 00 1e 01 00 01 00 54 02 16 WrapNonExceptionThrows 01
        $bytes1 = { 08 01 00 08 00 00 00 00 00 1e 01 00 01 00 54 02
                    16 57 72 61 70 4e 6f 6e 45 78 63 65 70 74 69 6f 
                    6e 54 68 72 6f 77 73 01 }
        // 00 00 BSJB...v2.0.50727 00 00 00 00 05 00
        // 00 00 BSJB...v4.0.30319 00 00 00 00 05 00
        $bytes2 = { 00 00 42 53 4a 42 01 00 01 00 00 00 00 00 0c 00 
                    00 00 76 3? 2e 3? 2e ?? ?? ?? ?? ?? 00 00 00 00
                    05 00 }
        // #Strings...#US...#GUID...#Blob
        $bytes3 = { 00 00 23 53 74 72 69 6e 67 73 00 00 00 00 [5] 00 
                    00 00 23 55 53 00 [5] 00 00 00 23 47 55 49 44 00 
                    00 00 [6] 00 00 23 42 6c 6f 62 00 00 00 }
        // .GetString.set_WorkingDirectory.WaitForExit.Close.Thread.System.Threading.Sleep.ToInt32.get_MainModule.ProcessModule.get_FileName.Split.
        $bytes4 = { 00 47 65 74 53 74 72 69 6e 67 00 73 65 74 5f 57
                    6f 72 6b 69 6e 67 44 69 72 65 63 74 6f 72 79 00
                    57 61 69 74 46 6f 72 45 78 69 74 00 43 6c 6f 73
                    65 00 54 68 72 65 61 64 00 53 79 73 74 65 6d 2e
                    54 68 72 65 61 64 69 6e 67 00 53 6c 65 65 70 00
                    54 6f 49 6e 74 33 32 00 67 65 74 5f 4d 61 69 6e
                    4d 6f 64 75 6c 65 00 50 72 6f 63 65 73 73 4d 6f
                    64 75 6c 65 00 67 65 74 5f 46 69 6c 65 4e 61 6d
                    65 00 53 70 6c 69 74 00 }
    condition:
        uint16(0) == 0x5a4d and 3 of ($bytes*) and all of ($s*)
}

rule INDICATOR_PY_Packed_PyMinifier {
    meta:
        author = "ditekSHen"
        description = "Detects python code potentially obfuscated using PyMinifier"
    strings:
        $s1 = "exec(lzma.decompress(base64.b64decode("
    condition:
        (uint32(0) == 0x6f706d69 or uint16(0) == 0x2123 or uint16(0) == 0x0a0d or uint16(0) == 0x5a4d) and all of them
}

rule INDICATOR_EXE_Packed_BoxedApp {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with BoxedApp"
        snort2_sid = "930037-930042"
        snort3_sid = "930013-930014"
    strings:
        $s1 = "BoxedAppSDK_HookFunction" fullword ascii
        $s2 = "BoxedAppSDK_StaticLib.cpp" ascii
        $s3 = "embedding BoxedApp into child processes: %s" ascii
        $s4 = "GetCommandLineA preparing to intercept" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains ".bxpck"
            )
        )
}

rule INDICATOR_EXE_Packed_eXPressor {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with eXPressor"
        snort2_sid = "930043-930048"
        snort3_sid = "930015-930016"
    strings:
        $s1 = "eXPressor_InstanceChecker_" fullword ascii
        $s2 = "This application was packed with an Unregistered version of eXPressor" ascii
        $s3 = ", please visit www.cgsoftlabs.ro" ascii
        $s4 = /eXPr-v\.\d+\.\d+/ ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains ".ex_cod"
            )
        )
}

rule INDICATOR_EXE_Packed_MEW {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with MEW"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "MEW" or
                pe.sections[i].name == "\x02\xd2u\xdb\x8a\x16\xeb\xd4"
            )
        )
}

rule INDICATOR_EXE_Packed_RLPack {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with RLPACK"
        snort2_sid = "930064-930066"
        snort3_sid = "930023"
    strings:
        $s1 = ".packed" fullword ascii
        $s2 = ".RLPack" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".RLPack"
            )
        )
}

rule INDICATOR_EXE_Packed_Cassandra {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Cassandra/CyaX"
    strings:
        $s1 = "AntiEM" fullword ascii wide
        $s2 = "AntiSB" fullword ascii wide
        $s3 = "Antis" fullword ascii wide
        $s4 = "XOR_DEC" fullword ascii wide
        $s5 = "StartInject" fullword ascii wide
        $s6 = "DetectGawadaka" fullword ascii wide
        $c1 = "CyaX-Sharp" ascii wide
        $c2 = "CyaX_Sharp" ascii wide
        $c3 = "CyaX-PNG" ascii wide
        $c4 = "CyaX_PNG" ascii wide
        $pdb = "\\CyaX\\obj\\Debug\\CyaX.pdb" ascii wide
    condition:
        (uint16(0) == 0x5a4d and (4 of ($s*) or 2 of ($c*) or $pdb)) or (7 of them)
}

rule INDICATOR_EXE_Packed_Themida {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Themida"
        snort2_sid = "930067-930069"
        snort3_sid = "930024"
    strings:
        $s1 = ".themida" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".themida"
            )
        )
}

rule INDICATOR_EXE_Packed_SilentInstallBuilder {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Silent Install Builder"
        snort2_sid = "930070-930072"
        snort3_sid = "930025"
    strings:
        $s1 = "C:\\Users\\Operations\\Source\\Workspaces\\Sib\\Sibl\\Release\\Sibuia.pdb" fullword ascii
        $s2 = "->mb!Silent Install Builder Demo Package." fullword wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_NyanXCat_CSharpLoader {
    meta:
        author = "ditekSHen"
        description = "Detects .NET executables utilizing NyanX-CAT C# Loader"
        snort2_sid = "930073-930075"
        snort3_sid = "930026"
    strings:
        $s1 = { 00 50 72 6f 67 72 61 6d 00 4c 6f 61 64 65 72 00 4e 79 61 6e 00 }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_Loader {
    meta:
        author = "ditekSHen"
        description = "Detects packed executables observed in Molerats"
    strings:
        $l1 = "loaderx86.dll" fullword ascii
        $l2 = "loaderx86" fullword ascii
        $l3 = "loaderx64.dll" fullword ascii
        $l4 = "loaderx64" fullword ascii
        $s1 = "ImportCall_Zw" wide
        $s2 = "DllInstall" ascii wide
        $s3 = "evb*.tmp" fullword wide
        $s4 = "WARNING ZwReadFileInformation" ascii
        $s5 = "LoadLibrary failed with module " fullword wide
    condition:
        uint16(0) == 0x5a4d and 2 of ($l*) and 4 of ($s*)
}

rule INDICATOR_EXE_Packed_Bonsai {
    meta:
         author = "ditekSHen"
        description = "Detects .NET executables developed using Bonsai"
    strings:
        $bonsai1 = "<Bonsai." ascii
        $bonsai2 = "Bonsai.Properties" ascii
        $bonsai3 = "Bonsai.Core.dll" fullword wide
        $bonsai4 = "Bonsai.Design." wide
    condition:
        uint16(0) == 0x5a4d and 2 of ($bonsai*)
}

/*
Can lead to many FPs?

rule INDICATOR_EXE_Packed_UPolyX {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with UPolyX"
    strings:
        $s1 = { 81 fd 00 fb ff ff 83 d1 ?? 8d 14 2f 83 fd fc 76 ?? 8a 02 42 88 07 47 49 75 }
        $s2 = { e2 ?? ff ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s3 = { 55 8b ec ?? 00 bd 46 00 8b ?? b9 ?? 00 00 00 80 ?? ?? 51 }
        $s4 = { bb ?? ?? ?? ?? 83 ec 04 89 1c 24 ?? b9 ?? 00 00 00 80 33 }
        $s5 = { e8 00 00 00 00 59 83 c1 07 51 c3 c3 }
        $s6 = { 83 ec 04 89 ?? 24 59 ?? ?? 00 00 00 }
    condition:
        uint16(0) == 0x5a4d and 1 of them and
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains "UPX"
            )
        )
}
*/

rule INDICATOR_EXE_Packed_TriumphLoader {
    meta:
        author = "ditekSHen"
        description = "Detects TriumphLoader"
        snort2_sid = "920101"
        snort3_sid = "920099"
        clamav_sig = "INDICATOR.Packed.TriumphLoader"
    strings:
        $id1 = "User-Agent: TriumphLoader" ascii wide
        $id2 = "\\loader\\absent-loader-master\\client\\full\\absentclientfull\\absentclientfull\\absent\\json.hpp" wide
        $id3 = "\\triumphloader\\triumphloaderfiles\\triumph\\json.h" wide
        $s1 = "current == '\\\"'" fullword wide
        $s2 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263" ascii
        $s3 = "646566676869707172737475767778798081828384858687888990919293949596979899object key" fullword ascii
        $s4 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
        $s5 = "last - first >= 2 + (-kMinExp - 1) + std::numeric_limits<FloatType>::max_digits10" fullword wide
        $s6 = "p2 <= (std::numeric_limits<std::uint64_t>::max)() / 10" fullword wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($id*) or all of ($s*) or (3 of ($s*) and 1 of ($id*)) or (4 of them and pe.imphash() == "784001f4b755832ae9085d98afc9ce83"))
}

rule INDICATOR_EXE_Packed_LLVMLoader {
    meta:
        author = "ditekSHen"
        description = "Detects LLVM obfuscator/loader"
        clamav_sig = "INDICATOR.Packed.LLVMLoader"
    strings:
        $s1 = "exeLoaderDll_LLVMO.dll" fullword ascii
        $b = { 64 6c 6c 00 53 74 61 72 74 46 75 6e 63 00 00 00
               ?? ?? 00 00 00 00 00 00 00 00 00 ?? 96 01 00 00
               ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00
               00 00 00 00 00 00 00 00 00 00 00 ?? ?? 45 78 69
               74 50 72 6f 63 65 73 73 00 4b 45 52 4e 45 4c 33
               32 2e 64 6c 6c 00 00 00 00 00 00 }
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x0158) and ((pe.exports("StartFunc") and 1 of ($s*)) or all of ($s*) or ($b))
}

rule INDICATOR_EXE_Packed_NoobyProtect {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with NoopyProtect"
    strings:
        $s1 = "NoobyProtect SE" ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "SE"
            )
        )
}

rule INDICATOR_EXE_Packed_nBinder {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with nBinder"
    strings:
        $s1 = "This file was created using nBinder" ascii
        $s2 = "Warning: Contains binded files that may pose a security risk." ascii
        $s3 = "a file created with nBinder" ascii
        $s4 = "name=\"NKProds.nBinder.Unpacker\" type=\"win" ascii
        $s5 = "<description>nBinder Unpacker. www.nkprods.com</description>" ascii
        $s6 = "nBinder Unpacker (C) NKProds" wide
        $s7 = "\\Proiecte\\nBin" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_EXE_Packed_SmartAssembly {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with SmartAssembly"
    strings:
        $s1 = "PoweredByAttribute" fullword ascii
        $s2 = "SmartAssembly.Attributes" fullword ascii
        $s3 = "Powered by SmartAssembly" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_EXE_Packed_AgileDotNet {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Agile.NET / CliSecure"
    strings:
        $x1 = "AgileDotNetRT" fullword ascii
        $x2 = "AgileDotNetRT64" fullword ascii
        $x3 = "<AgileDotNetRT>" fullword ascii
        $x4 = "AgileDotNetRT.dll" fullword ascii
        $x5 = "AgileDotNetRT64.dll" fullword ascii
        $x6 = "get_AgileDotNet" ascii
        $x7 = "useAgileDotNetStackFrames" fullword ascii
        $x8 = "AgileDotNet." ascii
        $x9 = "://secureteam.net/webservices" ascii
        $x10 = "AgileDotNetProtector." ascii
        $s1 = "Callvirt" fullword ascii
        $s2 = "_Initialize64" fullword ascii
        $s3 = "_AtExit64" fullword ascii
        $s4 = "DomainUnload" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and 2 of ($s*)) or all of ($s*))
}

rule INDICATOR_EXE_Packed_Fody {
    meta:
        author = "ditekSHen"
        description = "Detects executables manipulated with Fody"
    strings:
        $s1 = "ProcessedByFody" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_Costura {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Costura DotNetGuard"
    strings:
        $s1 = "DotNetGuard" fullword ascii
        $s2 = "costura." ascii wide
        $s3 = "AssemblyLoader" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_SimplePolyEngine {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Sality Polymorphic Code Generator or Simple Poly Engine or Sality"
    strings:
        $s1 = "Simple Poly Engine v" ascii
        $b1 = "yrf<[LordPE]" ascii
        $b2 = "Hello world!" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($b*))
}

rule INDICATOR_EXE_Packed_dotNetProtector {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with dotNetProtector"
    strings:
        $s1 = "dotNetProtector" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_DotNetReactor {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with unregistered version of .NET Reactor"
    strings:
        $s1 = "is protected by an unregistered version of Eziriz's\".NET Reactor\"!" wide
        $s2 = "is protected by an unregistered version of .NET Reactor!\" );</script>" wide
        $s3 = "is protected by an unregistered version of Eziriz's \".NET Reactor\"!" wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Dotfuscator {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Dotfuscator"
    strings:
        $s1 = "DotfuscatorAttribute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_DNGuard {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with DNGuard"
    strings:
        $s1 = "DNGuard Runtime library" wide
        $s2 = "[*=*]This application is expired ![*=*]" fullword wide
        $s3 = "DNGuard.Runtime" ascii wide
        $s4 = "EnableHVM" ascii
        $s5 = "DNGuard.SDK" ascii
        $s6 = "DNGuard HVM Runtime" wide
        $s7 = "HVMRuntm.dll" wide
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_EXE_Packed_NETProtectIO {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with NETProtect.IO"
    strings:
        $s1 = "NETProtect.IO v" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_KoiVM {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with or use KoiVM"
    strings:
        $s1 = "KoiVM v" ascii wide
        $s2 = "DarksVM " ascii wide
        $s3 = "Koi.NG" ascii wide
        $s4 = "KoiVM." ascii wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Goliath {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Goliath"
    strings:
        $s1 = "ObfuscatedByGoliath" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Babel {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Babel"
        snort = "930043-930044"
    strings:
        $s1 = "BabelObfuscatorAttribute" fullword ascii
        $m1 = ";babelvm;smoketest" ascii wide
        $m2 = { 62 00 61 00 62 00 65 00 6c 00 76 00 6d [1-20] 73 00 6d 00 6f 00 6b 00 65 00 74 00 65 00 73 00 74 }
        $m3 = "babelvm" wide
        $m4 = "smoketest" wide
        $m5 = /lic[A-F0-9]{8}/ ascii wide // in particular 'lic70F93782'
    condition:
        ((uint16(0) == 0x5a4d and 1 of ($s*)) or (2 of ($m*)))
}

rule INDICATOR_EXE_Packed_GEN01 {
    meta:
        author = "ditekSHen"
        description = "Detect packed .NET executables. Mostly AgentTeslaV4."
    strings:
        $c1 = "com.apple.Safari" fullword ascii
        $c2 = "Unable to resolve HTTP prox" fullword ascii
        $c3 = "rotcetorP rekciP laitnederC swodniW$" fullword ascii
        $c4 = "laitnederC drowssaP beW swodniW$" fullword ascii
        $s1 = "Accounts" fullword wide
        $s2 = "logins" fullword wide
        $s3 = "sha512" fullword wide
        $s4 = "credential" fullword wide
    condition:
        uint16(0) == 0x5a4d and 2 of ($c*) and all of ($s*)
}

rule INDICATOR_EXE_Packed_CryptoProtector {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with CryptoProtector / CryptoObfuscator"
    strings:
        $s1 = "CryptoObfuscator" ascii
        $s2 = "CryptoProtector [{0}]" wide
        $e1 = /[A-F0-9]{7,8}\.Crypto/ ascii
    condition:
        uint16(0) == 0x5a4d and all of ($s*) or (($s1) and #e1 > 10) or all of them
}

rule INDICATOR_EXE_Packed_Yano {
  meta:
      author = "ditekSHen"
      description = "Detects executables packed with Yano Obfuscator"
  strings:
      $s1 = "YanoAttribute" fullword ascii
      $s2 = "StripAfterObfuscation" fullword ascii
  condition:
      uint16(0) == 0x5a4d and all of them
}

rule SUSP_OBF_PyArmor_Jan24
{
	meta:
		description = "Detects PyArmor python code obfuscation. PyArmor is used by various threat actors like BatLoader"
		author = "Jonathan Peters"
		date = "2024-01-16"
		reference = "https://www.trendmicro.com/en_us/research/23/h/batloader-campaigns-use-pyarmor-pro-for-evasion.html"
		hash = "2727a418f31e8c0841f8c3e79455067798a1c11c2b83b5c74d2de4fb3476b654"
		score = 65
	strings:
		$ = "__pyarmor__" ascii
		$ = "pyarmor_runtime" ascii
    $ = "pyarmor(__" ascii
		$ = { 50 79 61 72 6D 6F 72 20 [5] 20 28 70 72 6F 29 }
		$ = { 5F 5F 61 72 6D 6F 72 5F ( 65 78 69 74 | 77 72 61 70 | 65 6E 74 65 72 ) 5F 5F }
	condition:
		2 of them
}

rule SUSP_OBF_NET_Reactor_Native_Stub_Jan24 {
	meta:
		description = "Detects native packer stub for version 4.5-4.7 of .NET Reactor. A pirated copy of version 4.5 of this commercial obfuscation solution is used by various malware families like BlackBit, RedLine, AgentTesla etc."
		author = "Jonathan Peters"
		date = "2024-01-05"
		reference = "https://notes.netbytesec.com/2023/08/understand-ransomware-ttps-blackbit.html"
		hash = "6e8a7adf680bede7b8429a18815c232004057607fdfbf0f4b0fb1deba71c5df7"
		score = 70
	strings:
		$op = {C6 44 24 18 E0 C6 44 24 19 3B C6 44 24 1A 8D C6 44 24 1B 2A C6 44 24 1C A2 C6 44 24 1D 2A C6 44 24 1E 2A C6 44 24 1F 41 C6 44 24 20 D3 C6 44 24 21 20 C6 44 24 22 64 C6 44 24 23 06 C6 44 24 24 8A C6 44 24 25 F7 C6 44 24 26 3D C6 44 24 27 9D C6 44 24 28 D9 C6 44 24 29 EE C6 44 24 2A 15 C6 44 24 2B 68 C6 44 24 2C F4 C6 44 24 2D 76 C6 44 24 2E B9 C6 44 24 2F 34 C6 44 24 30 BF C6 44 24 31 1E C6 44 24 32 E7 C6 44 24 33 78 C6 44 24 34 98 C6 44 24 35 E9 C6 44 24 36 6F C6 44 24 37 B4}
	condition:
		for any i in (0..pe.number_of_resources-1) : (pe.resources[i].name_string == "_\x00_\x00")
		and $op
}

rule SUSP_OBF_NET_Reactor_Indicators_Jan24
{
	meta:
		description = "Detects indicators of .NET Reactors managed obfuscation. Reactor is a commercial obfuscation solution, pirated versions are often abused by threat actors."
		author = "Jonathan Peters"
		date = "2024-01-09"
		reference = "https://www.eziriz.com/dotnet_reactor.htm"
		hash = "be842a9de19cfbf42ea5a94e3143d58390a1abd1e72ebfec5deeb8107dddf038"
		score = 65
	strings:
		$ = { 33 7B 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 7D 00 }
		$ = { 3C 50 72 69 76 61 74 65 49 6D 70 6C 65 6D 65 6E 74 61 74 69 6F 6E 44 65 74 61 69 6C 73 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }
		$ = { 3C 4D 6F 64 75 6C 65 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }
	condition:
      uint16(0) == 0x5a4d
		and 2 of them
}

rule SUSP_OBF_NET_ConfuserEx_Packer_Jan24 {
	meta:
		description = "Detects binaries packed with ConfuserEx compression packer. This feature compresses and encrypts the actual image into a stub that unpacks and loads the original image on runtime."
		author = "Jonathan Peters"
		date = "2024-01-09"
		reference = "https://github.com/yck1509/ConfuserEx/tree/master"
		hash = "2570bd4c3f564a61d6b3d589126e0940af27715e1e8d95de7863579fbe25f86f"
		score = 70
	strings:
		$s1 = "GCHandle" ascii
		$s2 = "GCHandleType" ascii

		$op1 = { 5A 20 89 C0 3F 14 6A 5E [8-20] 5A 20 FB 56 4D 44 6A 5E 6D 9E }
		$op2 = { 20 61 FF 6F 00 13 ?? 06 13 ?? 16 13 [10-20] 20 1F 3F 5E 00 5A}
		$op3 = { 16 91 7E [3] 04 17 91 1E 62 60 7E [3] 04 18 91 1F 10 62 60 7E [3] 04 19 91 1F 18 62 }
	condition:
		uint16(0) == 0x5a4d
		and all of ($s*)
		and 2 of ($op*)
}

rule PEiD_Bundle_v100_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 21 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
    condition:
        $a at pe.entry_point

}
rule PluginToExe_v101_BoB_BobSoft_additional: PEiD
{
    strings:
        $a = { E8 00 00 00 00 29 C0 5D 81 ED C6 41 40 00 50 8F 85 71 40 40 00 50 FF 95 A5 41 40 00 89 85 6D 40 40 00 FF 95 A1 41 40 00 50 FF 95 B5 41 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 B9 41 40 00 89 85 75 40 40 00 EB 6C 6A 01 8F 85 71 40 40 00 6A 58 6A }
    condition:
        $a at pe.entry_point

}

rule PEiD_Bundle_v102_v104_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
    condition:
        $a at pe.entry_point

}
rule PEiD_Bundle_v100_BoB_BobSoft_additional: PEiD
{
    strings:
        $a = { 60 E8 21 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
    condition:
        $a at pe.entry_point

}
rule Splash_Bitmap_v100_With_Unpack_Code_BoB_Bobsoft: PEiD
{
    strings:
        $a = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 6A 40 }
    condition:
        $a at pe.entry_point

}
rule PEiD_Bundle_v100_v101_BoB_BobSoft_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
    condition:
        $a at pe.entry_point

}
rule PEiD_Bundle_V102_DLL_BoB_BobSoft: PEiD
{
    strings:
        $a = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PluginToExe_v102_BoB_BobSoft: PEiD
{
    strings:
        $a = { E8 00 00 00 00 29 C0 5D 81 ED 32 42 40 00 50 8F 85 DD 40 40 00 50 FF 95 11 42 40 00 89 85 D9 40 40 00 FF 95 0D 42 40 00 50 FF 95 21 42 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 25 42 40 00 89 85 E1 40 40 00 EB 6C 6A 01 8F 85 DD 40 40 00 6A 58 6A 40 FF 95 15 42 40 00 89 85 D5 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 15 42 40 00 89 47 1C C7 07 58 00 }
        $b = { E8 00 00 00 00 29 C0 5D 81 ED 32 42 40 00 50 8F 85 DD 40 40 00 50 FF 95 11 42 40 00 89 85 D9 40 40 00 FF 95 0D 42 40 00 50 FF 95 21 42 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 25 42 40 00 89 85 E1 40 40 00 EB 6C 6A 01 8F 85 DD 40 40 00 6A 58 6A }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PEiD_Bundle_v102_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
    condition:
        $a at pe.entry_point

}
rule PEiD_Bundle_v104_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 A0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
    condition:
        $a at pe.entry_point

}
rule PEiD_Bundle_V101_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
    condition:
        $a at pe.entry_point

}
rule PEiD_Bundle_102_DLL_BoB_BobSoft: PEiD
{
    strings:
        $a = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Imploder_v104_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 A0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
    condition:
        $a at pe.entry_point

}
rule PEiD_Bundle_v101_BoB_BobSoft_additional: PEiD
{
    strings:
        $a = { 60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
    condition:
        $a at pe.entry_point

}
rule PEiD_Bundle_V100_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 21 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
    condition:
        $a at pe.entry_point

}
rule PEiD_Bundle_V102_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
    condition:
        $a at pe.entry_point

}
rule PluginToExe_v101_BoB_BobSoft: PEiD
{
    strings:
        $a = { E8 00 00 00 00 29 C0 5D 81 ED C6 41 40 00 50 8F 85 71 40 40 00 50 FF 95 A5 41 40 00 89 85 6D 40 40 00 FF 95 A1 41 40 00 50 FF 95 B5 41 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 B9 41 40 00 89 85 75 40 40 00 EB 6C 6A 01 8F 85 71 40 40 00 6A 58 6A 40 FF 95 A9 41 40 00 89 85 69 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 A9 41 40 00 89 47 1C C7 07 58 00 00 00 C7 47 20 00 08 00 00 C7 47 18 01 00 00 00 C7 47 34 04 10 88 00 8D 8D B9 40 40 00 89 4F 0C 8D 8D DB 40 40 00 89 4F 30 FF B5 69 40 40 00 FF 95 95 41 40 00 FF 77 1C 8F 85 75 40 40 00 8B 9D 6D 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 75 40 40 00 6A 00 81 C3 ?? ?? 00 00 FF D3 83 C4 10 83 BD 71 40 40 00 00 74 10 FF 77 1C FF 95 AD 41 40 00 57 FF 95 AD 41 40 00 6A 00 FF 95 9D 41 40 00 }
        $b = { E8 00 00 00 00 29 C0 5D 81 ED C6 41 40 00 50 8F 85 71 40 40 00 50 FF 95 A5 41 40 00 89 85 6D 40 40 00 FF 95 A1 41 40 00 50 FF 95 B5 41 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 B9 41 40 00 89 85 75 40 40 00 EB 6C 6A 01 8F 85 71 40 40 00 6A 58 6A }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule BobPack_v100_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED ?? ?? ?? ?? E8 3D 00 00 00 89 85 ?? ?? ?? ?? 89 C2 B8 5D 0A 00 00 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01 }
    condition:
        $a at pe.entry_point

}
rule BobSoft_Mini_Delphi_BoB_BobSoft_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 }
    condition:
        $a at pe.entry_point

}
rule BobSoft_Mini_Delphi_BoB_BobSoft: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 53 56 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 }
    condition:
        $a at pe.entry_point

}
rule PEiD_Bundle_v100_v101_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 ?? 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
    condition:
        $a at pe.entry_point

}
rule BobPack_v100_BoB_BobSoft_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED ?? ?? ?? ?? E8 3D 00 00 00 89 85 ?? ?? ?? ?? 89 C2 B8 5D 0A 00 00 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01 }
    condition:
        $a at pe.entry_point

}
rule PluginToExe_v102_BoB_BobSoft_additional: PEiD
{
    strings:
        $a = { E8 00 00 00 00 29 C0 5D 81 ED 32 42 40 00 50 8F 85 DD 40 40 00 50 FF 95 11 42 40 00 89 85 D9 40 40 00 FF 95 0D 42 40 00 50 FF 95 21 42 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 25 42 40 00 89 85 E1 40 40 00 EB 6C 6A 01 8F 85 DD 40 40 00 6A 58 6A }
    condition:
        $a at pe.entry_point

}
rule PEiD_Bundle_v101_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
    condition:
        $a at pe.entry_point

}
rule Splash_Bitmap_v100_BoB_Bobsoft: PEiD
{
    strings:
        $a = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 6A 00 }
    condition:
        $a at pe.entry_point

}
rule PluginToExe_v100_BoB_BobSoft_additional: PEiD
{
    strings:
        $a = { E8 00 00 00 00 29 C0 5D 81 ED D1 40 40 00 50 FF 95 B8 40 40 00 89 85 09 40 40 00 FF 95 B4 40 40 00 89 85 11 40 40 00 50 FF 95 C0 40 40 00 8A 08 80 F9 22 75 07 50 FF 95 C4 40 40 00 89 85 0D 40 40 00 8B 9D 09 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF }
    condition:
        $a at pe.entry_point

}
rule PEiD_Bundle_v102_v103_DLL_BoB_BobSoft: PEiD
{
    strings:
        $a = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PluginToExe_v100_BoB_BobSoft: PEiD
{
    strings:
        $a = { E8 00 00 00 00 29 C0 5D 81 ED D1 40 40 00 50 FF 95 B8 40 40 00 89 85 09 40 40 00 FF 95 B4 40 40 00 89 85 11 40 40 00 50 FF 95 C0 40 40 00 8A 08 80 F9 22 75 07 50 FF 95 C4 40 40 00 89 85 0D 40 40 00 8B 9D 09 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 0D 40 40 00 6A 00 81 C3 ?? ?? ?? 00 FF D3 83 C4 10 FF 95 B0 40 40 00 }
        $b = { E8 00 00 00 00 29 C0 5D 81 ED D1 40 40 00 50 FF 95 B8 40 40 00 89 85 09 40 40 00 FF 95 B4 40 40 00 89 85 11 40 40 00 50 FF 95 C0 40 40 00 8A 08 80 F9 22 75 07 50 FF 95 C4 40 40 00 89 85 0D 40 40 00 8B 9D 09 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PEiD_Bundle_v102_v103_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
    condition:
        $a at pe.entry_point

}

rule PESpin_V07_cyberbobnbsp_nbsp_SignByfly_20080312: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB FF 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? EB 01 ?? 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? EB FB ?? 83 04 24 0C C3 }
    condition:
        $a at pe.entry_point

}
rule PESpin_V13betaX_cyberbobnbsp_nbsp_SignByfly_20080311: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB ?? ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 }
    condition:
        $a at pe.entry_point

}
rule PESpin_V1304_cyberbobnbsp_nbsp_SignByfly_20080310: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? EB 01 ?? EB 0D ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB ?? ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 ?? ?? ?? ?? EB 06 ?? ?? ?? ?? ?? ?? F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 }
    condition:
        $a at pe.entry_point

}
rule PESpin_V041_cyberbob_20080312: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 02 D2 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 ?? ?? ?? ?? ?? 53 8F ?? ?? ?? ?? ?? BB ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 ?? 68 3C 01 00 00 59 8D ?? ?? ?? ?? ?? C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 ?? ?? ?? ?? 59 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 ?? E8 1A 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_v1304_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
        $b = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 CD 4E 40 00 8B 42 3C 03 C2 89 85 D7 4E 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D EB 4E 40 00 53 8F 85 E1 4C 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD 90 4F 40 00 8D 5B 04 8B 1B 89 9D 95 4F 40 00 E8 00 00 00 00 58 01 68 05 68 D3 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC FF 25 10 BB ?? 00 00 00 B9 84 12 00 00 8D BD C6 4F 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C EB 04 01 EB 0? }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PESpin_v01_Cyberbob_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 B3 28 40 00 8B 42 3C 03 C2 89 85 BD 28 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D D1 28 40 00 53 8F 85 C4 27 40 00 BB ?? 00 00 00 B9 A5 08 00 00 8D BD 75 29 40 00 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D BD AA 30 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 07 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D C4 28 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 59 81 C1 1D 00 00 00 52 51 C1 E9 05 23 D1 FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_03_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_v1304_Cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_v13beta_Cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_V10_cyberbob_20080312: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 C8 DC 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 ?? ?? ?? ?? ?? ?? ?? C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB FF 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? ?? ?? ?? 83 04 24 0C C3 }
    condition:
        $a at pe.entry_point

}
rule PESpin_V01_cyberbob_20080312: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 ?? ?? ?? ?? ?? 53 8F 85 ?? ?? ?? ?? BB ?? ?? ?? ?? B9 A5 08 00 00 8D ?? ?? ?? ?? ?? 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D ?? ?? ?? ?? ?? C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 ?? ?? ?? ?? 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_13x_Cyberbob_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_01_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_1304_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_v11_Cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_03_cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B }
    condition:
        $a at pe.entry_point

}
rule PESpin_11_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 C8 DC 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_v07_Cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
        $b = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 88 39 40 00 8B 42 3C 03 C2 89 85 92 39 40 00 EB 01 DB 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D A6 39 40 00 53 8F 85 4A 38 40 00 BB ?? 00 00 00 B9 EC 0A 00 00 8D BD 36 3A 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 56 44 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 B3 5F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D 99 39 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PESpin_V041_cyberbobnbsp_nbsp_SignByfly_20080312: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 02 D2 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 ?? ?? ?? ?? ?? 53 8F ?? ?? ?? ?? ?? BB ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 ?? 68 3C 01 00 00 59 8D ?? ?? ?? ?? ?? C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 ?? ?? ?? ?? 59 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 ?? E8 1A 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_v07_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 88 39 40 00 8B 42 3C 03 C2 89 85 92 39 40 00 EB 01 DB 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D A6 39 40 00 53 8F 85 4A 38 40 00 BB ?? 00 00 00 B9 EC 0A 00 00 8D BD 36 3A 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 56 44 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 B3 5F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D 99 39 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_V01_cyberbobnbsp_nbsp_SignByfly_20080312: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 ?? ?? ?? ?? ?? 53 8F 85 ?? ?? ?? ?? BB ?? ?? ?? ?? B9 A5 08 00 00 8D ?? ?? ?? ?? ?? 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D ?? ?? ?? ?? ?? C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 ?? ?? ?? ?? 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_13beta_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 }
    condition:
        $a at pe.entry_point

}
rule PESPin_v13_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
        $b = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 0D 4F 40 00 8B 42 3C 03 C2 89 85 17 4F 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D 2B 4F 40 00 53 8F 85 21 4D 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD D0 4F 40 00 8D 5B 04 8B 1B 89 9D D5 4F 40 00 E8 00 00 00 00 58 01 68 05 68 F7 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PESpin_1304_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 }
    condition:
        $a at pe.entry_point

}
rule PESpin_0b_01_CyberBob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 }
    condition:
        $a at pe.entry_point

}
rule PESpin_13beta_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_V071_cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E }
    condition:
        $a at pe.entry_point

}
rule PESpin_v11_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
        $b = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 C3 4B 40 00 8B 42 3C 03 C2 89 85 CD 4B 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D E1 4B 40 00 53 8F 85 D7 49 40 00 BB ?? 00 00 00 B9 FE 11 00 00 8D BD 71 4C 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C C1 2C 24 06 F7 14 24 83 24 24 01 50 52 B8 83 B2 DC 12 05 44 4D 23 ED F7 64 24 08 8D 84 28 BD 2D 40 00 89 44 24 08 5A 58 8D 64 24 04 FF 64 24 FC FF EA EB 01 C8 E8 01 00 00 00 68 58 FE 48 1F 0F 84 94 02 00 00 75 01 9A 81 70 03 E8 98 68 EA 83 C0 21 8? }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PESpin_11_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_v01_Cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
        $b = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 B3 28 40 00 8B 42 3C 03 C2 89 85 BD 28 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D D1 28 40 00 53 8F 85 C4 27 40 00 BB ?? 00 00 00 B9 A5 08 00 00 8D BD 75 29 40 00 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D BD AA 30 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 07 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D C4 28 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 59 81 C1 1D 00 00 00 52 51 C1 E9 05 23 D1 FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PESpin_V03_cyberbob_20080312: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_07_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
        $b = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PESpin_v03_Cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_v11_Cyberbob_: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 C3 4B 40 00 8B 42 3C 03 C2 89 85 CD 4B 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D E1 4B 40 00 53 8F 85 D7 49 40 00 BB ?? 00 00 00 B9 FE 11 00 00 8D BD 71 4C 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C C1 2C 24 06 F7 14 24 83 24 24 01 50 52 B8 83 B2 DC 12 05 44 4D 23 ED F7 64 24 08 8D 84 28 BD 2D 40 00 89 44 24 08 5A 58 8D 64 24 04 FF 64 24 FC FF EA EB 01 C8 E8 01 00 00 00 68 58 FE 48 1F 0F 84 94 02 00 00 75 01 9A 81 70 03 E8 98 68 EA 83 C0 21 8? }
    condition:
        $a at pe.entry_point

}
rule PESpin_V1304_cyberbob_20080310: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? EB 01 ?? EB 0D ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB ?? ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 ?? ?? ?? ?? EB 06 ?? ?? ?? ?? ?? ?? F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 }
    condition:
        $a at pe.entry_point

}
rule PESpin_10_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_v11_by_cyberbob_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 C3 4B 40 00 8B 42 3C 03 C2 89 85 CD 4B 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D E1 4B 40 00 53 8F 85 D7 49 40 00 BB ?? 00 00 00 B9 FE 11 00 00 8D BD 71 4C 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C }
    condition:
        $a at pe.entry_point

}
rule PESpin_v03_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_V03_cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_V11_cyberbobnbsp_nbsp_SignByfly_20080311: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 ?? 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 ?? ?? ?? ?? ?? ?? F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? EB FB }
    condition:
        $a at pe.entry_point

}
rule PESpin_v13beta_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 ?? 4E 40 00 8B 42 3C 03 C2 89 85 ?? 4E 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D ?? 4E 40 00 53 8F 85 ?? 4C 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD ?? 4F 40 00 8D 5B 04 8B 1B 89 9D ?? 4F 40 00 E8 00 00 00 00 58 01 68 05 68 BC 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC FF 25 10 BB ?? 00 00 00 B9 84 12 00 00 8D BD ?? 4F 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C }
    condition:
        $a at pe.entry_point

}
rule PESPin_v13_Cyberbob_: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 0D 4F 40 00 8B 42 3C 03 C2 89 85 17 4F 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D 2B 4F 40 00 53 8F 85 21 4D 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD D0 4F 40 00 8D 5B 04 8B 1B 89 9D D5 4F 40 00 E8 00 00 00 00 58 01 68 05 68 F7 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC }
    condition:
        $a at pe.entry_point

}
rule PESpin_v1304_Cyberbob_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_v10_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 C8 DC 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 D2 42 40 00 8B 42 3C 03 C2 89 85 DC 42 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D F0 42 40 00 53 8F 85 94 41 40 00 BB ?? 00 00 00 B9 8C 0B 00 00 8D BD 80 43 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 40 4E 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 FD 68 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_V11_cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E }
    condition:
        $a at pe.entry_point

}
rule PESpin_10_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 C8 DC 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESPin_13_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_V0b_cyberbobnbsp_nbsp_SignByfly_20080312: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 72 C8 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 26 E8 01 00 00 00 ?? 5A 33 C9 ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B ?? ?? ?? ?? ?? ?? 8B 59 24 03 DA 8B 1B ?? ?? ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 0C 5B 6A 17 59 30 0C 03 02 CB 4B 75 F8 40 8D 9D 41 8F 4E 00 50 53 81 2C 24 01 78 0E 00 ?? ?? ?? ?? ?? ?? C3 92 EB 15 68 ?? ?? ?? ?? ?? B9 ?? 08 00 00 ?? ?? ?? ?? ?? ?? 4F 30 1C 39 FE CB E2 F9 68 1D 01 00 00 59 ?? ?? ?? ?? ?? ?? C0 0C 39 02 E2 FA 68 ?? ?? ?? ?? 50 01 6C 24 04 E8 BD 09 00 00 33 C0 0F 84 C0 08 00 00 ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF E0 C3 8D 64 24 04 E8 53 0A 00 00 D7 58 5B 51 C3 F7 F3 32 DA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 2C 24 A3 00 00 00 58 ?? ?? ?? ?? ?? ?? 53 FF E0 }
    condition:
        $a at pe.entry_point

}
rule PESpin_v07_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
        $b = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 88 39 40 00 8B 42 3C 03 C2 89 85 92 39 40 00 EB 01 DB 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D A6 39 40 00 53 8F 85 4A 38 40 00 BB ?? 00 00 00 B9 EC 0A 00 00 8D BD 36 3A 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 56 44 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 B3 5F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D 99 39 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PESpin_v03_Eng_cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 }
    condition:
        $a at pe.entry_point

}
rule PESPin_13_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_v07_Cyberbob_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 88 39 40 00 8B 42 3C 03 C2 89 85 92 39 40 00 EB 01 DB 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D A6 39 40 00 53 8F 85 4A 38 40 00 BB ?? 00 00 00 B9 EC 0A 00 00 8D BD 36 3A 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 56 44 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 B3 5F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D 99 39 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_07_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_03_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
        $b = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PESpin_V11_cyberbob_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E }
    condition:
        $a at pe.entry_point

}
rule PESpin_v10_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 C8 DC 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 D2 42 40 00 8B 42 3C 03 C2 89 85 DC 42 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D F0 42 40 00 53 8F 85 94 41 40 00 BB ?? 00 00 00 B9 8C 0B 00 00 8D BD 80 43 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 40 4E 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 FD 68 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_V13betaX_cyberbob_20080311: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB ?? ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 }
    condition:
        $a at pe.entry_point

}
rule PESpin_v11_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 C3 4B 40 00 8B 42 3C 03 C2 89 85 CD 4B 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D E1 4B 40 00 53 8F 85 D7 49 40 00 BB ?? 00 00 00 B9 FE 11 00 00 8D BD 71 4C 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C C1 2C 24 06 F7 14 24 83 24 24 01 50 52 B8 83 B2 DC 12 05 44 4D 23 ED F7 64 24 08 8D 84 28 BD 2D 40 00 89 44 24 08 5A 58 8D 64 24 04 FF 64 24 FC FF EA EB 01 C8 E8 01 00 00 00 68 58 FE 48 1F 0F 84 94 02 00 00 75 01 9A 81 70 03 E8 98 68 EA 83 C0 21 8? }
    condition:
        $a at pe.entry_point

}
rule PESpin_v03_Eng_cyberbob_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 0D 4F 40 00 8B 42 3C 03 C2 89 85 17 4F 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D 2B 4F 40 00 53 8F 85 21 4D 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD D0 4F 40 00 8D 5B 04 8B 1B 89 9D D5 4F 40 00 E8 00 00 00 00 58 01 68 05 68 F7 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC }
    condition:
        $a at pe.entry_point

}
rule PESpin_v03_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_v13beta_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
        $b = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 ?? 4E 40 00 8B 42 3C 03 C2 89 85 ?? 4E 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D ?? 4E 40 00 53 8F 85 ?? 4C 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD ?? 4F 40 00 8D 5B 04 8B 1B 89 9D ?? 4F 40 00 E8 00 00 00 00 58 01 68 05 68 BC 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC FF 25 10 BB ?? 00 00 00 B9 84 12 00 00 8D BD ?? 4F 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PESPin_v13_Cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        $a at pe.entry_point

}
rule PESpin_V10_cyberbobnbsp_nbsp_SignByfly_20080312: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 C8 DC 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 ?? ?? ?? ?? ?? ?? ?? C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB FF 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? ?? ?? ?? 83 04 24 0C C3 }
    condition:
        $a at pe.entry_point

}
rule PESpin_v13beta2_Cyberbob_: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 ?? 4E 40 00 8B 42 3C 03 C2 89 85 ?? 4E 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D ?? 4E 40 00 53 8F 85 ?? 4C 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD ?? 4F 40 00 8D 5B 04 8B 1B 89 9D ?? 4F 40 00 E8 00 00 00 00 58 01 68 05 68 BC 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC FF 25 10 BB ?? 00 00 00 B9 84 12 00 00 8D BD ?? 4F 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C }
    condition:
        $a at pe.entry_point

}
rule PESpin_v10_Cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 C8 DC 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 D2 42 40 00 8B 42 3C 03 C2 89 85 DC 42 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D F0 42 40 00 53 8F 85 94 41 40 00 BB ?? 00 00 00 B9 8C 0B 00 00 8D BD 80 43 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 40 4E 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 FD 68 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_V071_cyberbob_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 C3 4B 40 00 8B 42 3C 03 C2 89 85 CD 4B 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D E1 4B 40 00 53 8F 85 D7 49 40 00 BB ?? 00 00 00 B9 FE 11 00 00 8D BD 71 4C 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C C1 2C 24 06 F7 14 24 83 24 24 01 50 52 B8 83 B2 DC 12 05 44 4D 23 ED F7 64 24 08 8D 84 28 BD 2D 40 00 89 44 24 08 5A 58 8D 64 24 04 FF 64 24 FC FF EA EB 01 C8 E8 01 00 00 00 68 58 FE 48 1F 0F 84 94 02 00 00 75 01 9A 81 70 03 E8 98 68 EA 83 C0 21 80 40 FB EB A2 40 02 00 E0 91 32 68 CB 00 00 00 59 8D BD A3 5D 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 }
    condition:
        $a at pe.entry_point

}
rule PESpin_V11_cyberbob_20080311: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 ?? 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 ?? ?? ?? ?? ?? ?? F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? EB FB }
    condition:
        $a at pe.entry_point

}
rule PESpin_V132_cyberbobnbsp_nbsp_SignByfly_20080310: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 17 E6 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? EB 01 ?? EB 0D FF E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB FF E8 02 00 00 00 ?? ?? 5A 81 ?? ?? ?? ?? ?? 83 EA FE 89 95 A9 57 40 00 2B C0 2B C9 83 F1 06 09 85 CB 57 40 00 9C D3 2C 24 80 C1 FB 21 0C 24 50 52 B8 36 C7 09 FF 05 FE 37 F6 00 F7 64 24 08 8D 84 28 B1 35 40 00 89 44 24 08 5A 58 8D 64 24 04 FF 64 24 FC CD 20 BB 69 74 58 0B C1 C3 }
    condition:
        $a at pe.entry_point

}
rule PESpin_13x_Cyberbob: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 }
        $b = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PESpin_v07_Cyberbob_: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 88 39 40 00 8B 42 3C 03 C2 89 85 92 39 40 00 EB 01 DB 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D A6 39 40 00 53 8F 85 4A 38 40 00 BB ?? 00 00 00 B9 EC 0A 00 00 8D BD 36 3A 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 56 44 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 B3 5F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D 99 39 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PESpin_V0b_cyberbob_20080312: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 72 C8 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 26 E8 01 00 00 00 ?? 5A 33 C9 ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B ?? ?? ?? ?? ?? ?? 8B 59 24 03 DA 8B 1B ?? ?? ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 0C 5B 6A 17 59 30 0C 03 02 CB 4B 75 F8 40 8D 9D 41 8F 4E 00 50 53 81 2C 24 01 78 0E 00 ?? ?? ?? ?? ?? ?? C3 92 EB 15 68 ?? ?? ?? ?? ?? B9 ?? 08 00 00 ?? ?? ?? ?? ?? ?? 4F 30 1C 39 FE CB E2 F9 68 1D 01 00 00 59 ?? ?? ?? ?? ?? ?? C0 0C 39 02 E2 FA 68 ?? ?? ?? ?? 50 01 6C 24 04 E8 BD 09 00 00 33 C0 0F 84 C0 08 00 00 ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF E0 C3 8D 64 24 04 E8 53 0A 00 00 D7 58 5B 51 C3 F7 F3 32 DA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 2C 24 A3 00 00 00 58 ?? ?? ?? ?? ?? ?? 53 FF E0 }
    condition:
        $a at pe.entry_point

}
rule PESpin_v1304_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 CD 4E 40 00 8B 42 3C 03 C2 89 85 D7 4E 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D EB 4E 40 00 53 8F 85 E1 4C 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD 90 4F 40 00 8D 5B 04 8B 1B 89 9D 95 4F 40 00 E8 00 00 00 00 58 01 68 05 68 D3 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC FF 25 10 BB ?? 00 00 00 B9 84 12 00 00 8D BD C6 4F 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C EB 04 01 EB 0? }
    condition:
        $a at pe.entry_point

}
rule PESPin_v13_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 CD 4E 40 00 8B 42 3C 03 C2 89 85 D7 4E 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D EB 4E 40 00 53 8F 85 E1 4C 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD 90 4F 40 00 8D 5B 04 8B 1B 89 9D 95 4F 40 00 E8 00 00 00 00 58 01 68 05 68 D3 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC FF 25 10 BB ?? 00 00 00 B9 84 12 00 00 8D BD C6 4F 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C EB 04 01 EB 04 CD EB FB 2B C1 2C 24 06 F7 14 24 83 24 24 01 50 52 B8 79 B2 DC 12 05 44 4D 23 ED F7 64 24 08 8D 84 28 20 2F 40 00 89 44 24 08 5A 58 8D 64 24 04 FF 64 24 FC FF EA EB EB 01 C8 E8 01 00 00 00 68 58 FE 48 1F 0F 84 94 02 00 00 75 01 9A 81 70 03 E8 98 68 EA 83 C0 21 80 40 FB EB A2 40 02 00 E0 91 32 68 CB 00 00 00 59 8D BD 7E 61 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 49 9C E8 03 00 00 00 EB 04 8D EB FB FF 83 04 24 0C C3 A3 C1 2C 24 06 F7 14 24 83 24 24 01 50 52 B8 61 B2 DC 12 05 44 4D 23 ED F7 64 24 08 8D 84 28 B2 2F 40 00 89 44 24 08 5A 58 8D 64 24 04 FF 64 24 FC 9A }
    condition:
        $a at pe.entry_point

}
rule PESpin_V07_cyberbob_20080312: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB FF 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? EB 01 ?? 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? EB FB ?? 83 04 24 0C C3 }
    condition:
        $a at pe.entry_point

}
rule PESpin_v11_by_cyberbob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 C3 4B 40 00 8B 42 3C 03 C2 89 85 CD 4B 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D E1 4B 40 00 53 8F 85 D7 49 40 00 BB ?? 00 00 00 B9 FE 11 00 00 8D BD 71 4C 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C }
    condition:
        $a at pe.entry_point

}
rule PESpin_v01_Cyberbob_h_additional: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 }
    condition:
        $a at pe.entry_point

}
rule PESpin_v01_Cyberbob_h: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
        $b = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 B3 28 40 00 8B 42 3C 03 C2 89 85 BD 28 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D D1 28 40 00 53 8F 85 C4 27 40 00 BB ?? 00 00 00 B9 A5 08 00 00 8D BD 75 29 40 00 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D BD AA 30 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 07 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D C4 28 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 59 81 C1 1D 00 00 00 52 51 C1 E9 05 23 D1 FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PESpin_V132_cyberbob_20080310: PEiD
{
    strings:
        $a = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 17 E6 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? EB 01 ?? EB 0D FF E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB FF E8 02 00 00 00 ?? ?? 5A 81 ?? ?? ?? ?? ?? 83 EA FE 89 95 A9 57 40 00 2B C0 2B C9 83 F1 06 09 85 CB 57 40 00 9C D3 2C 24 80 C1 FB 21 0C 24 50 52 B8 36 C7 09 FF 05 FE 37 F6 00 F7 64 24 08 8D 84 28 B1 35 40 00 89 44 24 08 5A 58 8D 64 24 04 FF 64 24 FC CD 20 BB 69 74 58 0B C1 C3 }
    condition:
        $a at pe.entry_point
}

rule Obsidium_1337_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 27 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1350_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 20 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 ?? ?? ?? ?? EB 01 ?? EB 02 ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 }
        $b = { EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 20 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 04 ?? ?? ?? ?? 50 EB }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_v10061_additional: PEiD
{
    strings:
        $a = { E8 AF 1C 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1337_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 27 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1364_Obsidium_Software_20090428: PEiD
{
    strings:
        $a = { EB 02 ?? ?? 50 EB 04 ?? ?? ?? ?? E8 29 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 1E EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 64 FF 30 EB 02 ?? ?? 64 89 20 EB 01 ?? EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 ?? ?? ?? ?? EB 02 ?? ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1338_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 ?? EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 01 ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 57 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1400_Obsidium_Software_20091005: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? E8 ?? 00 00 00 EB 01 ?? EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 71 49 EB 01 ?? EB 03 ?? ?? ?? 33 C0 EB 01 ?? 64 FF 30 EB 01 ?? 64 89 20 EB 02 ?? ?? EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? 58 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 ?? 00 00 00 EB 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? C3 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_10061_Obsidium_Software: PEiD
{
    strings:
        $a = { E8 AF 1C 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1339_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 28 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 CF 27 00 00 }
        $b = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 28 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 03 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_1333_Obsidium_Software_SignByhaggar: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 27 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1337_20070623_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 27 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 F7 26 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v10059_Final_additional: PEiD
{
    strings:
        $a = { E8 AB 1C }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v1250_Obsidium_Software: PEiD
{
    strings:
        $a = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_13017_Obsidium_software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 28 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1342_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 50 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_13037_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1341_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 01 ?? E8 2A 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 C3 27 00 00 }
        $b = { EB 01 ?? E8 2A 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_1258_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 7B 21 00 00 }
        $b = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_v1304_Obsidium_Software_h_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1258_V133X_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 01 ?? E8 ?? 00 00 00 EB 02 ?? ?? EB }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1258_V133X_Obsidium_Software_Sign_by_fly: PEiD
{
    strings:
        $a = { EB 01 ?? E8 ?? 00 00 00 EB 02 ?? ?? EB }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v13037_Obsidium_Software_h_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1333_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1352_Obsidium_Software_SignByfly: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8 }
        $b = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_V1355_Obsidium_Software_20080411: PEiD
{
    strings:
        $a = { EB 01 ?? E8 2B 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 ?? ?? ?? ?? EB 01 ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 01 ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1352_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_10069_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 A3 1C 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v1300_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1333_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B ?? 24 0C EB 01 ?? 83 ?? B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1338_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 ?? EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 01 ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 57 27 00 00 }
        $b = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 ?? EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 01 ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_1337_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 27 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1337_20070620_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 27 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v1304_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? E8 3B 26 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V125_Obsidium_Software: PEiD
{
    strings:
        $a = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1304_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 ?? 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_vxxxx_Obsidium_Software: PEiD
{
    strings:
        $a = { E8 47 19 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1250_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V12_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 77 1E 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1258_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 01 ?? E8 ?? 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_vxxxx: PEiD
{
    strings:
        $a = { E9 5D 01 ?? ?? CE D1 CE CE 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 }
        $b = { E8 47 19 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_v10061: PEiD
{
    strings:
        $a = { E8 47 }
        $b = { E8 AF 1C 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_13013_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 01 ?? E8 26 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8 13 26 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_13013_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 01 ?? E8 26 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8 13 26 00 00 }
        $b = { EB 01 ?? E8 26 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 01 ?? 33 C0 EB 03 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_V1322_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 27 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1300_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 22 EB 02 ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 47 26 00 00 }
        $b = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_V1200_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 3F 1E 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1300_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 81 2C 24 CA C2 41 00 EB 04 64 6B 88 18 5D E8 00 00 00 00 EB 04 64 6B 88 18 81 2C 24 86 00 00 00 EB 04 64 6B 88 18 8B 85 9C C2 41 00 EB 04 64 6B 88 18 29 04 24 EB 04 64 6B 88 18 EB 04 64 6B 88 18 8B 04 24 EB 04 64 6B 88 18 89 85 9C C2 41 00 EB 04 64 6B 88 18 58 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 C2 50 00 EB D3 5B F3 68 89 5C 24 48 5C 24 58 FF 8D 5C 24 58 5B 83 C3 4C 75 F4 5A 8D 71 78 75 09 81 F3 EB FF 52 BA 01 00 83 EB FC 4A FF 71 0F 75 19 8B 5C 24 00 00 81 33 50 53 8B 1B 0F FF C6 75 1B 81 F3 EB 87 1C 24 8B 8B 04 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 58 EB FF F0 EB FF C0 83 E8 FD EB FF 30 E8 C9 00 00 00 89 E0 EB FF D0 EB FF 71 0F 83 C0 01 EB FF 70 F0 71 EE EB FA EB 83 C0 14 EB FF 70 ED }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1311_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 27 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 03 ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1341_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 01 ?? E8 2A 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 C3 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1200_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 28 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 4F 26 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v13037_Obsidium_Software_h: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 }
        $b = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_V1400Beta_Obsidium_Software_SignByfly_20080102_additional: PEiD
{
    strings:
        $a = { EB 01 ?? E8 2F 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_13037_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1400Beta_Obsidium_Software_SignByfly_20080102: PEiD
{
    strings:
        $a = { EB 01 ?? E8 2F 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 01 ?? E9 ?? ?? ?? ?? EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 }
        $b = { EB 01 ?? E8 2F 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_1334_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 03 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1400Beta_Obsidium_Software_20080102: PEiD
{
    strings:
        $a = { EB 01 ?? E8 2F 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 01 ?? E9 ?? ?? ?? ?? EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_11114_11115_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 3F 1D 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V12_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 77 1E 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1337_20070623_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 27 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1336_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? ?? ?? ?? ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1357_Obsidium_Softwarenbsp_nbsp_SignByfly_20080521: PEiD
{
    strings:
        $a = { EB 01 ?? E8 ?? 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 ?? ?? ?? ?? EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 03 ?? ?? ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 01 ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1357_Obsidium_Software_20080521: PEiD
{
    strings:
        $a = { EB 01 ?? E8 ?? 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 ?? ?? ?? ?? EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 03 ?? ?? ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 01 ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1331_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 02 ?? ?? E8 5F 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1331_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 02 ?? ?? E8 5F 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v1250_Obsidium_Software_h: PEiD
{
    strings:
        $a = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1339_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 28 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 CF 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_unknown_version: PEiD
{
    strings:
        $a = { EB 01 ?? 50 EB 03 ?? ?? ?? E8 ?? 00 00 00 EB 03 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v1111: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 E7 1C 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1334_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 }
        $b = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 03 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_V1363_Obsidium_Softwarenbsp_nbsp_SignByfly_20080730: PEiD
{
    strings:
        $a = { EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? E8 ?? 00 00 00 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 26 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0 EB 02 ?? ?? 64 FF 30 EB 01 ?? 64 89 20 EB 01 ?? EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 ?? 00 00 00 EB 03 ?? ?? ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1311_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 27 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 03 ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1350_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 20 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 04 ?? ?? ?? ?? 50 EB }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1300_Obsidium_Software_h: PEiD
{
    strings:
        $a = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1304_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 ?? 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v1300_Obsidium_Software_h: PEiD
{
    strings:
        $a = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B 50 EB 03 8A 0B 93 33 C0 EB 02 28 B9 8B 00 EB 01 04 C3 EB 04 65 B3 54 0A E9 FA 00 00 00 EB 01 A2 E8 D5 FF FF FF EB 02 2B 49 EB 03 7C 3E 76 58 EB 04 B8 94 92 56 EB 01 72 64 67 8F 06 00 00 EB 02 23 72 83 C4 04 EB 02 A9 CB E8 47 26 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1363_Obsidium_Software_20080730: PEiD
{
    strings:
        $a = { EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? E8 ?? 00 00 00 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 26 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0 EB 02 ?? ?? 64 FF 30 EB 01 ?? 64 89 20 EB 01 ?? EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 ?? 00 00 00 EB 03 ?? ?? ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_13021_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 26 00 00 }
        $b = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_V1342_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 C3 27 00 00 }
        $b = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 50 EB 04 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_V1361_Obsidium_Softwarenbsp_nbsp_SignByfly_20080521: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? E8 ?? 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 ?? EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 64 FF 30 EB 04 ?? ?? ?? ?? 64 89 20 EB 01 ?? EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 01 ?? E8 ?? FF FF FF EB 01 ?? EB 03 ?? ?? ?? EB 01 ?? EB 03 ?? ?? ?? 64 8F 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? 58 EB 02 ?? ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V12X_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { E8 0E 00 00 00 33 C0 8B 54 24 0C 83 82 B8 00 00 00 0D C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1300_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V130X_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B ?? ?? ?? EB 04 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v1304_Obsidium_Software_h: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 }
        $b = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? E8 3B 26 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_v13037_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1334_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B ?? 24 0C EB 01 ?? 83 ?? B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v1300_Obsidium_Software_h_additional: PEiD
{
    strings:
        $a = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1355_Obsidium_Softwarenbsp_nbsp_SignByfly_20080411: PEiD
{
    strings:
        $a = { EB 01 ?? E8 2B 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 ?? ?? ?? ?? EB 01 ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 01 ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v1111_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 ?? 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v1250_Obsidium_Software_h_additional: PEiD
{
    strings:
        $a = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1333_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1338_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 ?? EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 01 ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 57 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1360_Obsidium_Software_20080730: PEiD
{
    strings:
        $a = { EB 02 ?? ?? 50 EB 01 ?? E8 ?? 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 1F EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0 EB 01 ?? 64 FF 30 EB 04 ?? ?? ?? ?? 64 89 20 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 ?? 00 00 00 EB 01 ?? E8 ?? FF FF FF EB 01 ?? EB 03 ?? ?? ?? EB 02 ?? ?? EB 02 ?? ?? 64 8F 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1322_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 2A 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1354_Obsidium_Software_200800207: PEiD
{
    strings:
        $a = { EB 03 ?? ?? ?? E8 2D 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 25 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 5B 28 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1336_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? ?? ?? ?? ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1258_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 7B 21 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1336_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? ?? ?? ?? ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 }
        $b = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? ?? ?? ?? ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_1322_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 2A 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1353_Obsidium_Software_20080120: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 2B 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1360_Obsidium_Softwarenbsp_nbsp_SignByfly_20080730: PEiD
{
    strings:
        $a = { EB 02 ?? ?? 50 EB 01 ?? E8 ?? 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 1F EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0 EB 01 ?? 64 FF 30 EB 04 ?? ?? ?? ?? 64 89 20 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 ?? 00 00 00 EB 01 ?? E8 ?? FF FF FF EB 01 ?? EB 03 ?? ?? ?? EB 02 ?? ?? EB 02 ?? ?? 64 8F 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1341_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 01 ?? E8 2A 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 C3 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1334_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1353_Obsidium_Software_SignByfly_20080120: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 2B 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 }
        $b = { EB 02 ?? ?? E8 2B 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 04 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_V1354_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 03 ?? ?? ?? E8 2D 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 25 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1342_Obsidium_Softwarenbsp_nbsp_SignByfly: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 C3 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V125_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1361_Obsidium_Software_20080521: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? E8 ?? 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 ?? EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 64 FF 30 EB 04 ?? ?? ?? ?? 64 89 20 EB 01 ?? EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 01 ?? E8 ?? FF FF FF EB 01 ?? EB 03 ?? ?? ?? EB 01 ?? EB 03 ?? ?? ?? 64 8F 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? 58 EB 02 ?? ?? E8 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V12X_Obsidium_Software: PEiD
{
    strings:
        $a = { E8 0E 00 00 00 33 C0 8B 54 24 0C 83 82 B8 00 00 00 0D C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1332_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 01 ?? E8 2B 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 3B 27 00 00 }
        $b = { EB 01 ?? E8 2B 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 02 ?? ?? 33 C0 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_vxxxx_additional: PEiD
{
    strings:
        $a = { E8 47 19 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1200_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 3F 1E 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1333_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1339_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 28 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 CF 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V130X_Obsidium_Software_Sign_by_fly: PEiD
{
    strings:
        $a = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B ?? ?? ?? EB 04 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1304_Obsidium_Software_h: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_13017_Obsidium_software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 28 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1332_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 01 ?? E8 2B 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 3B 27 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1258_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 01 ?? E8 ?? 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1354_Obsidium_Software_SignByfly_200800207: PEiD
{
    strings:
        $a = { EB 03 ?? ?? ?? E8 2D 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 25 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 5B 28 00 00 }
        $b = { EB 03 ?? ?? ?? E8 2D 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 25 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 50 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_1322_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 2A 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v1331_Obsidium_Software_h: PEiD
{
    strings:
        $a = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1300_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v10059_Final: PEiD
{
    strings:
        $a = { E8 AF }
        $b = { E8 AB 1C }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_v1304_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 }
        $b = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? E8 3B 26 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_v1331_Obsidium_Software_h_additional: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 2A 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_V1311_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 27 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_v1250_Obsidium_Software_: PEiD
{
    strings:
        $a = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1337_20070623_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 27 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 F7 26 00 00 }
        $b = { EB 02 ?? ?? E8 27 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Obsidium_V1342_Obsidium_Softwarenbsp_nbsp_SignByfly_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 27 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_1250_Obsidium_Software: PEiD
{
    strings:
        $a = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Obsidium_13021_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB }
    condition:
        $a at pe.entry_point

}   

rule Pelock_10x: PEiD
{
    strings:
        $a = { 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45 }
    condition:
        $a at pe.entry_point

}
rule PELOCKnt_204: PEiD
{
    strings:
        $a = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 }
    condition:
        $a at pe.entry_point

}
rule PELOCKnt_204_additional: PEiD
{
    strings:
        $a = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 }
    condition:
        $a at pe.entry_point

}
rule PELOCknt_201: PEiD
{
    strings:
        $a = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD 20 EB 60 EB 03 CD 20 03 E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 04 CD EB 03 CD EB 02 CD 20 EB 03 CD 20 EA FC EB 03 CD 20 69 E8 00 00 00 00 EB 02 EB 01 EB 01 EB 5E EB 03 CD 20 EB EB }
    condition:
        $a at pe.entry_point

}
rule PELOCknt_203: PEiD
{
    strings:
        $a = { EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB 01 EB 01 EB E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 01 EB EB 02 CD 20 EB 03 CD 20 EB FC EB 02 C7 85 E8 00 00 00 00 EB 03 CD 20 EA 5E EB 03 CD 20 69 0F 01 4E F4 EB 03 CD 20 EB EB 01 EB }
    condition:
        $a at pe.entry_point

}
rule PELOCknt_202: PEiD
{
    strings:
        $a = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD 20 60 EB 03 CD 20 EB E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 04 CD 20 EB 02 EB 02 CD 20 EB 03 CD 20 EA FC EB 03 CD 20 69 E8 00 00 00 00 EB 02 EB 01 EB 01 EB 5E EB 02 CD 20 0F 01 4E }
    condition:
        $a at pe.entry_point

}

rule NsPacK_V33_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D ?? ?? ?? ?? 89 85 }
    condition:
        $a at pe.entry_point

}
rule NsPack_30_North_Star_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 }
    condition:
        $a at pe.entry_point

}
rule NsPacK_V31_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74 }
    condition:
        $a at pe.entry_point

}
rule NsPacK_V30_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? E9 ?? ?? E8 ?? ?? 83 }
    condition:
        $a at pe.entry_point

}
rule NsPack_34_North_Star: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF 80 38 01 0F 84 42 02 00 00 C6 00 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 }
        $b = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF 80 38 01 0F 84 42 02 00 00 C6 00 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule NsPack_V14_LiuXingPing_: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00 }
    condition:
        $a at pe.entry_point

}
rule Anti007_V25_V26_NsPacK_Private: PEiD
{
    strings:
        $a = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 53 }
    condition:
        $a at pe.entry_point

}
rule NsPack_29_North_Star: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8A 06 3C 00 74 12 8B F5 8D B5 ?? ?? FF FF 8A 06 3C 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }
        $b = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8A 06 3C 00 74 12 8B F5 8D B5 ?? ?? FF FF 8A 06 3C 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule NsPack_v37_North_Star: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 8D ?? ?? ?? FF 80 39 01 0F 84 42 02 00 00 C6 01 01 8B C5 2B 85 ?? ?? ?? FF 89 85 ?? ?? ?? FF 01 85 ?? ?? ?? FF 8D B5 ?? ?? ?? FF 01 06 55 56 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? ?? FF 85 C0 0F 84 69 03 00 00 89 85 ?? ?? ?? FF E8 00 00 00 00 5B B9 67 03 00 00 03 D9 50 53 E8 B0 02 00 00 5E 5D 8B 36 8B FD 03 BD ?? ?? ?? FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 34 01 13 8B 33 03 7B 04 57 51 53 FF B5 ?? ?? ?? FF FF B5 ?? ?? ?? FF 8B D6 8B CF 8B 85 ?? ?? ?? FF 05 AA 05 00 00 FF D0 5B 59 5F 83 F9 00 74 05 83 C3 08 EB C7 68 00 80 00 00 6A 00 FF B5 ?? ?? ?? FF FF 95 ?? ?? ?? FF 8D B5 ?? ?? ?? FF 8B 4E 08 8D 56 10 8B 36 8B FE 83 F9 00 74 3F 8A 07 47 2C E8 3C 01 77 F7 8B 07 80 7A 01 00 74 14 8A 1A 38 1F 75 E9 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 EB 0A 8A 5F 04 86 C4 C1 C0 10 86 C4 2B C7 03 C6 89 07 83 C7 05 80 EB E8 8B C3 E2 C6 E8 3A 01 00 00 8D 8D }
    condition:
        $a at pe.entry_point

}
rule NsPack_v31_North_Star: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 }
        $b = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 68 00 80 00 00 6A 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule NsPacK_V36_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 83 38 01 0F 84 47 02 00 00 }
    condition:
        $a at pe.entry_point

}
rule NsPack_31_by_North_Star_Liu_Xing_Ping: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 }
    condition:
        $a at pe.entry_point

}
rule Anti007_V27_V35_NsPacK_Private_additional: PEiD
{
    strings:
        $a = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 54 }
    condition:
        $a at pe.entry_point

}
rule NsPack_v23_North_Star_h: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD }
    condition:
        $a at pe.entry_point

}
rule NsPack_14_Liuxingping_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 ?? ?? 40 00 2D ?? ?? 40 00 }
    condition:
        $a at pe.entry_point

}
rule NsPack_v37_North_Star_h: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 8D ?? ?? ?? FF 80 39 01 0F 84 42 02 00 00 C6 01 01 8B C5 2B 85 ?? ?? ?? FF 89 85 ?? ?? ?? FF 01 85 ?? ?? ?? FF 8D B5 ?? ?? ?? FF 01 06 55 56 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? ?? FF 85 C0 0F 84 69 03 00 00 89 85 ?? ?? ?? FF E8 00 00 00 00 5B B9 67 03 00 00 03 D9 50 53 E8 B0 02 00 00 5E 5D 8B 36 8B FD 03 BD ?? ?? ?? FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 34 01 13 8B 33 03 7B 04 57 51 53 FF B5 ?? ?? ?? FF FF B5 ?? ?? ?? FF 8B D6 8B CF 8B 85 ?? ?? ?? FF 05 AA 05 00 00 FF D0 5B 59 5F 83 F9 00 74 05 83 C3 08 EB C7 68 00 80 00 00 6A 00 FF B5 ?? ?? ?? FF FF 95 ?? ?? ?? FF 8D B5 ?? ?? ?? FF 8B 4E 08 8D 56 10 8B 36 8B FE 83 F9 00 74 3F 8A 07 47 2C E8 3C 01 77 F7 8B 07 80 7A 01 00 74 14 8A 1A 38 1F 75 E9 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 EB 0A 8A 5F 04 86 C4 C1 C0 10 86 C4 2B C7 03 C6 89 07 83 C7 05 80 EB E8 8B C3 E2 C6 E8 3A 01 00 00 8D 8D }
    condition:
        $a at pe.entry_point

}
rule MSLRH_032a_fake_nSPack_13_emadicius: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D3 FE FF FF 8B 06 83 F8 00 74 11 8D B5 DF FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 }
    condition:
        $a at pe.entry_point

}
rule NsPack_30_by_North_Star_Liu_Xing_Ping_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 55 F9 FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 7D F9 FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 11 F9 FF FF 89 95 }
    condition:
        $a at pe.entry_point

}
rule Anti007_NsPacK_Private_additional: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule MSLRH_v032a_fake_nSPack_13_emadicius_h: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D3 FE FF FF 8B 06 83 F8 00 74 11 8D B5 DF FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
    condition:
        $a at pe.entry_point

}
rule NsPack_14_by_North_Star_Liu_Xing_Ping_: PEiD
{
    strings:
        $a = { 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 }
    condition:
        $a at pe.entry_point

}
rule NsPacK_V36_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 83 38 01 0F 84 47 02 00 00 }
    condition:
        $a at pe.entry_point

}
rule NsPack_31_North_Star_h: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 }
    condition:
        $a at pe.entry_point

}
rule NsPacK_V34_V35_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 01 0F 84 }
    condition:
        $a at pe.entry_point

}
rule NSPack_Nort_Star_Software_urlwwwnsdsncom: PEiD
{
    strings:
        $a = { 83 F9 00 74 28 43 8D B5 ?? ?? FF FF 8B 16 56 51 53 52 56 FF 33 FF 73 04 8B 43 08 03 C2 50 FF 95 ?? ?? FF FF 5A 5B 59 5E 83 C3 0C E2 E1 61 9D E9 ?? ?? ?? FF 8B B5 ?? ?? FF FF 0B F6 0F 84 97 00 00 00 8B 95 ?? ?? FF FF 03 F2 83 3E 00 75 0E 83 7E 04 00 75 08 83 7E 08 00 75 02 EB 7A 8B 5E 08 03 DA 53 52 56 8D BD ?? ?? FF FF 03 7E 04 83 C6 0C 57 }
        $b = { 83 F9 00 74 28 43 8D B5 ?? ?? FF FF 8B 16 56 51 53 52 56 FF 33 FF 73 04 8B 43 08 03 C2 50 FF 95 ?? ?? FF FF 5A 5B 59 5E 83 C3 0C E2 E1 61 9D E9 ?? ?? ?? FF 8B B5 ?? ?? FF FF 0B F6 0F 84 97 00 00 00 8B 95 ?? ?? FF FF 03 F2 83 3E 00 75 0E 83 7E 04 00 75 08 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule NsPacK_Net_LiuXingPing_Sign_by_fly: PEiD
{
    strings:
        $a = { 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 BB 01 47 65 74 53 79 73 74 65 6D 49 6E 66 6F 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 5E 00 5F 43 6F 72 ?? ?? ?? 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C }
    condition:
        $a at pe.entry_point

}
rule nSPack_2x3x_NET_North_StarLiu_Xing_Ping: PEiD
{
    strings:
        $a = { FF 25 A4 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $b = { FF 25 A4 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule NsPacK_V34_V35_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 01 0F 84 }
    condition:
        $a at pe.entry_point

}
rule NsPack_v37_North_Star_h_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 8D ?? ?? ?? FF 80 39 01 0F 84 42 02 00 00 C6 01 01 8B C5 2B 85 ?? ?? ?? FF 89 85 ?? ?? ?? FF 01 85 ?? ?? ?? FF 8D B5 ?? ?? ?? FF 01 06 55 56 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? ?? FF 85 C0 0F 84 69 03 00 00 89 85 ?? ?? ?? FF E8 00 00 00 00 5B B9 67 03 00 00 03 D9 50 53 E8 B0 02 00 00 5E 5D 8B 36 8B FD 03 BD ?? ?? ?? FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 34 01 13 8B 33 03 7B 04 57 51 53 FF B5 ?? ?? ?? FF FF B5 ?? ?? ?? FF 8B D6 8B CF 8B 85 ?? ?? ?? FF 05 AA 05 00 00 FF D0 5B 59 5F 83 F9 00 74 05 83 C3 08 EB C7 68 00 80 00 00 6A 00 FF B5 ?? ?? ?? FF FF 95 ?? ?? ?? FF 8D B5 ?? ?? ?? FF 8B 4E 08 8D 56 10 8B 36 8B FE 83 F9 00 74 3F 8A 07 47 2C E8 3C 01 77 F7 8B 07 80 7A 01 00 74 14 8A 1A 38 1F 75 E9 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 EB 0A 8A 5F 04 86 C4 C1 C0 10 86 C4 2B C7 03 C6 89 07 83 C7 05 80 EB E8 8B C3 E2 C6 E8 3A 01 00 00 8D 8D }
    condition:
        $a at pe.entry_point

}
rule NsPack_29_North_Star_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD }
    condition:
        $a at pe.entry_point

}
rule nSpack_V11_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }
    condition:
        $a at pe.entry_point

}
rule nSpack_V23_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 70 61 63 6B 24 40 }
    condition:
        $a at pe.entry_point

}
rule nSpack_V30_LiuXingPing: PEiD
{
    strings:
        $a = { 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? E9 ?? ?? E8 ?? ?? 83 }
    condition:
        $a at pe.entry_point

}
rule nSpack_V23_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 70 61 63 6B 24 40 }
    condition:
        $a at pe.entry_point

}
rule NsPack_v31_North_Star_h_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 68 00 80 00 00 6A 00 }
    condition:
        $a at pe.entry_point

}
rule nSpack_V13_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 }
    condition:
        $a at pe.entry_point

}
rule NsPacK_V37_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 80 39 01 0F ?? ?? ?? 00 00 }
    condition:
        $a at pe.entry_point

}
rule Anti007_V25_V26_NsPacK_Private_additional: PEiD
{
    strings:
        $a = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 53 }
    condition:
        $a at pe.entry_point

}
rule NsPack_14_by_North_Star_Liu_Xing_Ping: PEiD
{
    strings:
        $a = { 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 }
    condition:
        $a at pe.entry_point

}
rule NSPack_3x_Liu_Xing_Ping_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D }
    condition:
        $a at pe.entry_point

}
rule NsPack_31_Liu_Xing_Ping: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 }
    condition:
        $a at pe.entry_point

}
rule NsPacK_V31_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74 }
    condition:
        $a at pe.entry_point

}
rule NsPack_V11_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }
    condition:
        $a at pe.entry_point

}
rule Anti007_V10_V2X_NsPacK_Private_additional: PEiD
{
    strings:
        $a = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 45 78 69 74 }
    condition:
        $a at pe.entry_point

}
rule nSpack_V31_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74 }
    condition:
        $a at pe.entry_point

}
rule NsPack_V2X_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 6E 73 70 61 63 6B 24 40 }
    condition:
        $a at pe.entry_point

}
rule Anti007_V10_V2X_NsPacK_Private: PEiD
{
    strings:
        $a = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 45 78 69 74 }
    condition:
        $a at pe.entry_point

}
rule nSpack_V2x_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 }
        $b = { 6E 73 70 61 63 6B 24 40 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule MSLRH_v032a_fake_nSPack_13_emadicius: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D3 FE FF FF 8B 06 83 F8 00 74 11 8D B5 DF FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
    condition:
        $a at pe.entry_point

}
rule nSpack_V2x_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 }
    condition:
        $a at pe.entry_point

}
rule MSLRH_032a_fake_nSPack_13_emadicius_additional: PEiD
{
    strings:
        $a = { E9 A6 00 00 00 B0 7B 40 00 78 60 40 00 7C 60 40 00 00 00 00 00 B0 3F 00 00 12 62 40 00 4E 65 6F 4C 69 74 65 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 43 6F 6D 70 72 65 73 73 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 38 2C 31 }
    condition:
        $a at pe.entry_point

}
rule NsPack_V13_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 }
    condition:
        $a at pe.entry_point

}
rule NsPack_31_by_North_Star_Liu_Xing_Ping_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 }
    condition:
        $a at pe.entry_point

}
rule NsPack_V11_LiuXingPing_: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }
    condition:
        $a at pe.entry_point

}
rule Anti007_V27_V35_NsPacK_Private: PEiD
{
    strings:
        $a = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 54 }
    condition:
        $a at pe.entry_point

}
rule NsPack_v23_North_Star_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 56 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 54 03 00 00 03 D9 50 53 E8 9D 02 00 00 61 }
    condition:
        $a at pe.entry_point

}
rule NsPacK_V37_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 80 39 01 0F ?? ?? ?? 00 00 }
    condition:
        $a at pe.entry_point

}
rule NsPack_v23_North_Star: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD }
        $b = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 56 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 54 03 00 00 03 D9 50 53 E8 9D 02 00 00 61 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule NsPack_v23_North_Star_h_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 56 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 54 03 00 00 03 D9 50 53 E8 9D 02 00 00 61 }
    condition:
        $a at pe.entry_point

}
rule nSPack_2x_North_StarLiu_Xing_Ping_additional: PEiD
{
    strings:
        $a = { FF FF 8B 4E 08 8D 56 10 8B 36 8B FE 83 F9 00 74 3F 8A 07 47 2C E8 3C 01 77 F7 8B 07 80 7A 01 }
    condition:
        $a at pe.entry_point

}
rule NSPack_3x_Liu_Xing_Ping: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF ?? 38 01 0F 84 ?? 02 00 00 ?? 00 01 }
    condition:
        $a at pe.entry_point

}
rule NSPack_Nort_Star_Software_httpwwwnsdsncom: PEiD
{
    strings:
        $a = { 83 F9 00 74 28 43 8D B5 ?? ?? FF FF 8B 16 56 51 53 52 56 FF 33 FF 73 04 8B 43 08 03 C2 50 FF 95 ?? ?? FF FF 5A 5B 59 5E 83 C3 0C E2 E1 61 9D E9 ?? ?? ?? FF 8B B5 ?? ?? FF FF 0B F6 0F 84 97 00 00 00 8B 95 ?? ?? FF FF 03 F2 83 3E 00 75 0E 83 7E 04 00 75 08 }
    condition:
        $a at pe.entry_point

}
rule NsPack_V2X_LiuXingPing: PEiD
{
    strings:
        $a = { 6E 73 70 61 63 6B 24 40 }
    condition:
        $a at pe.entry_point

}
rule NsPack_3x_Liu_Xing_Ping: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D }
    condition:
        $a at pe.entry_point

}
rule NsPack_31_North_Star_h_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 }
    condition:
        $a at pe.entry_point

}
rule NsPack_14_Liuxingping: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 ?? ?? 40 00 2D ?? ?? 40 00 }
    condition:
        $a at pe.entry_point

}
rule NsPack_14_by_North_Star_Liu_Xing_Ping_additional: PEiD
{
    strings:
        $a = { 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 }
    condition:
        $a at pe.entry_point

}
rule NsPacK_V30_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? ?? ?? 66 8B 06 66 83 F8 00 74 }
    condition:
        $a at pe.entry_point

}
rule NsPack_V14_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00 }
    condition:
        $a at pe.entry_point

}
rule NSPack_Nort_Star_Software_urlwwwnsdsncom_additional: PEiD
{
    strings:
        $a = { 83 F9 00 74 28 43 8D B5 ?? ?? FF FF 8B 16 56 51 53 52 56 FF 33 FF 73 04 8B 43 08 03 C2 50 FF 95 ?? ?? FF FF 5A 5B 59 5E 83 C3 0C E2 E1 61 9D E9 ?? ?? ?? FF 8B B5 ?? ?? FF FF 0B F6 0F 84 97 00 00 00 8B 95 ?? ?? FF FF 03 F2 83 3E 00 75 0E 83 7E 04 00 75 08 }
    condition:
        $a at pe.entry_point

}
rule nSpack_V29_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? ?? ?? 8A 06 3C 00 74 12 8B F5 8D B5 }
    condition:
        $a at pe.entry_point

}
rule NsPack_23_Liu_Xing_Ping: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD }
    condition:
        $a at pe.entry_point

}
rule NsPack_30_by_North_Star_Liu_Xing_Ping: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 55 F9 FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 7D F9 FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 11 F9 FF FF 89 95 }
    condition:
        $a at pe.entry_point

}
rule NsPack_V14_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00 }
    condition:
        $a at pe.entry_point

}
rule nSpack_V13_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 }
    condition:
        $a at pe.entry_point

}
rule nSPack_2x3x_NET_North_StarLiu_Xing_Ping_additional: PEiD
{
    strings:
        $a = { FF 25 A4 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule NsPack_v31_North_Star_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 68 00 80 00 00 6A 00 }
    condition:
        $a at pe.entry_point

}
rule NsPacK_V33_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 00 74 }
    condition:
        $a at pe.entry_point

}
rule nSPack_2x_North_StarLiu_Xing_Ping: PEiD
{
    strings:
        $a = { FF FF 8B 4E 08 8D 56 10 8B 36 8B FE 83 F9 00 74 3F 8A 07 47 2C E8 3C 01 77 F7 8B 07 80 7A 01 }
    condition:
        $a at pe.entry_point

}
rule nSPack_1x2x_North_StarLiu_Xing_Ping: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 }
    condition:
        $a at pe.entry_point

}
rule Anti007_NsPacK_Private: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule NsPack_V11_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }
    condition:
        $a at pe.entry_point

}
rule NsPack_v31_North_Star_h: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 }
    condition:
        $a at pe.entry_point

}
rule NsPacK_Net_LiuXingPing: PEiD
{
    strings:
        $a = { 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 BB 01 47 65 74 53 79 73 74 65 6D 49 6E 66 6F 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 5E 00 5F 43 6F 72 ?? ?? ?? 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C }
    condition:
        $a at pe.entry_point

}
rule NsPack_30_North_Star: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }
        $b = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule NsPack_34_North_Star_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF 80 38 01 0F 84 42 02 00 00 C6 00 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v123_RC1: PEiD
{
    strings:
        $a = { 68 01 ?? ?? 00 E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v123_RC4_build_0807_dll_Alexey_Solodovnikov_h_additional: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v123_RC4_build_0807_exe_Alexey_Solodovnikov_h: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $b = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASProtect_130824_beta: PEiD
{
    strings:
        $a = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v12_Alexey_Solodovnikov_h1: PEiD
{
    strings:
        $a = { 90 60 E8 1B 00 00 00 E9 FC 8D B5 0F 06 00 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB 04 5D 45 55 C3 E9 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_vxx: PEiD
{
    strings:
        $a = { 60 ?? ?? ?? ?? ?? 90 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 DD }
    condition:
        $a at pe.entry_point

}
rule ASProtect_vxx_additional: PEiD
{
    strings:
        $a = { 90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_ASProtect_Anorganix_additional: PEiD
{
    strings:
        $a = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_23_SKE_build_0426_Beta_additional: PEiD
{
    strings:
        $a = { 68 01 60 40 00 E8 01 00 00 00 C3 C3 0D 6C 65 3E 09 84 BB 91 89 38 D0 5A 1D 60 6D AF D5 51 2D A9 2F E1 62 D8 C1 5A 8D 6B 6E 94 A7 F9 1D 26 8C 8E FB 08 A8 7E 9D 3B 0C DF 14 5E 62 14 7D 78 D0 6E }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_2122_dll_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v123_RC4_build_0807_dll_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v12x_New_Strain_additional: PEiD
{
    strings:
        $a = { 68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_23_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 E5 0B 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v11_BRS_additional: PEiD
{
    strings:
        $a = { 60 E9 ?? 05 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v_If_you_know_this_version_post_on_PEiD_board: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v12x_additional: PEiD
{
    strings:
        $a = { 00 00 68 01 ?? ?? ?? C3 AA }
    condition:
        $a at pe.entry_point

}
rule ASProtect_V2X_DLL_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 ?? ?? 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ?? ?? ?? ?? 03 DD }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v132: PEiD
{
    strings:
        $a = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v_If_you_know_this_version_post_on_PEiD_board_h2_additional: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_12_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 68 01 ?? ?? ?? C3 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_23_Alexey_Solodovnikov_h: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 E5 0B 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v12_Alexey_Solodovnikov_h1_additional: PEiD
{
    strings:
        $a = { 90 ?? 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v20_additional: PEiD
{
    strings:
        $a = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2C }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v123_RC4_build_0807_exe_Alexey_Solodovnikov_h_additional: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_123_RC4_build_0807_exe_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v20: PEiD
{
    strings:
        $a = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 }
        $b = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2C }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASProtect_v12x_New_Strain: PEiD
{
    strings:
        $a = { 68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v11_BRS: PEiD
{
    strings:
        $a = { 68 01 }
        $b = { 60 E9 ?? 05 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASProtect_123_RC4_build_0807_dll_Alexey_Solodovnikov_h: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_10_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 01 00 00 00 90 5D 81 ED ?? ?? ?? 00 BB ?? ?? ?? 00 03 DD 2B 9D }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_21x_dll_Alexey_Solodovnikov_h_additional: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_2122_exe_Alexey_Solodovnikov_h: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }
        $b = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C }
        $c = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASProtect_V2X_Registered_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 68 01 ?? ?? ?? E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_ASProtect: PEiD
{
    strings:
        $a = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v123_RC1_additional: PEiD
{
    strings:
        $a = { 53 60 BD ?? ?? ?? ?? 8D 45 ?? 8D 5D ?? E8 ?? ?? ?? ?? 8D }
    condition:
        $a at pe.entry_point

}
rule ASProtect_11_MTE_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_2122_exe_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v123_RC4_build_0807_dll_Alexey_Solodovnikov_h: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $b = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASProtect_v_If_you_know_this_version_post_on_PEiD_board_h2: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $b = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40 }
        $c = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASProtect_SKE_21x_exe_Alexey_Solodovnikov_h_additional: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_02_ASProtect: PEiD
{
    strings:
        $a = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v21x: PEiD
{
    strings:
        $a = { BB E9 60 9C FC BF B9 F3 AA 9D 61 C3 55 8B }
    condition:
        $a at pe.entry_point

}
rule ASProtect_123_RC4_build_0807_exe_Alexey_Solodovnikov_h_additional: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_ASProtect_Anorganix: PEiD
{
    strings:
        $a = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_2122_dll_Alexey_Solodovnikov_h: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }
        $b = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule AHTeam_EP_Protector_03_fake_ASProtect_10_FEUERRADER: PEiD
{
    strings:
        $a = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 01 00 00 00 90 5D 81 ED 00 00 00 00 BB 00 00 00 00 03 DD 2B 9D }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_2122_dll_Alexey_Solodovnikov_h_additional: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v11_MTEb_additional: PEiD
{
    strings:
        $a = { 90 60 E9 ?? 04 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_133_21_Registered_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 68 01 ?? ?? ?? E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_20: PEiD
{
    strings:
        $a = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_23_SKE_build_0426_Beta: PEiD
{
    strings:
        $a = { 68 01 60 40 00 E8 01 00 00 00 C3 C3 0D 6C 65 3E 09 84 BB 91 89 38 D0 5A 1D 60 6D AF D5 51 2D A9 2F E1 62 D8 C1 5A 8D 6B 6E 94 A7 F9 1D 26 8C 8E FB 08 A8 7E 9D 3B 0C DF 14 5E 62 14 7D 78 D0 6E }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v11_additional: PEiD
{
    strings:
        $a = { 90 60 E8 1B ?? ?? ?? E9 FC }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v11_MTEc: PEiD
{
    strings:
        $a = { 90 60 E8 1B ?? ?? ?? E9 FC }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v11_MTEb: PEiD
{
    strings:
        $a = { 90 60 E8 1B E9 }
        $b = { 90 60 E9 ?? 04 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASProtect_v123_RC4_build_0807_exe_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $b = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASProtect_20_additional: PEiD
{
    strings:
        $a = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_123_RC4_build_0807_exe_Alexey_Solodovnikov_h: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_11_BRS_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E9 ?? 05 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v10_additional: PEiD
{
    strings:
        $a = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED D3 22 40 00 E8 04 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v12x: PEiD
{
    strings:
        $a = { 00 00 68 01 ?? ?? ?? C3 AA }
    condition:
        $a at pe.entry_point

}
rule ASProtect_V2X_DLL_Alexey_Solodovnikov_additional: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 ?? ?? 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ?? ?? ?? ?? 03 DD }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_02_ASProtect: PEiD
{
    strings:
        $a = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_21x_dll_Alexey_Solodovnikov_h: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_02_ASProtect_Anorganix: PEiD
{
    strings:
        $a = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }
    condition:
        $a at pe.entry_point

}
rule ASProtect_123_RC4_build_0807_dll_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_23_Alexey_Solodovnikov_h_additional: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 E5 0B 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_21x_dll_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v11_MTE: PEiD
{
    strings:
        $a = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v10: PEiD
{
    strings:
        $a = { 60 E8 01 ?? ?? ?? 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v11: PEiD
{
    strings:
        $a = { 60 E9 ?? 04 ?? ?? E9 ?? ?? ?? ?? ?? ?? ?? EE }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v12: PEiD
{
    strings:
        $a = { 68 01 C3 AA ?? }
        $b = { 68 01 ?? ?? ?? C3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASProtect_v_If_you_know_this_version_post_on_PEiD_board_additional: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_21x_exe_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $b = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASProtect_v12_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 90 60 E8 1B 00 00 00 E9 FC 8D B5 0F 06 00 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB 04 5D 45 55 C3 E9 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_11_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E9 ?? 04 00 00 E9 ?? ?? ?? ?? ?? ?? ?? EE }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v12_additional: PEiD
{
    strings:
        $a = { 68 01 ?? ?? 00 E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_123_RC4_130824_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 68 01 ?? ?? 00 E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v11_MTEc_additional: PEiD
{
    strings:
        $a = { 33 C0 BE ?? ?? 8B D8 B9 ?? ?? BF ?? ?? BA ?? ?? 47 4A 74 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_2122_exe_Alexey_Solodovnikov_h_additional: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_133_21_Registered_Alexey_Solodovnikov_additional: PEiD
{
    strings:
        $a = { 68 01 ?? ?? ?? E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_SKE_21x_exe_Alexey_Solodovnikov_h: PEiD
{
    strings:
        $a = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_123_RC4_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 68 01 F0 58 00 E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_123_RC4_build_0807_dll_Alexey_Solodovnikov_h_additional: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_01_ASProtect_Anorganix: PEiD
{
    strings:
        $a = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_02_ASProtect_Anorganix: PEiD
{
    strings:
        $a = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }
    condition:
        $a at pe.entry_point

}
rule ASProtect_122_123_Beta_21_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 68 01 E0 46 00 E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}
rule ASProtect_v11_MTE_additional: PEiD
{
    strings:
        $a = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }
    condition:
        $a at pe.entry_point

}

rule Crinkler_V01_V02_Rune_LHStubbe_and_Aske_Simon_Christensen: PEiD
{
    strings:
        $a = { B9 ?? ?? ?? ?? 01 C0 68 ?? ?? ?? ?? 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE ?? ?? ?? ?? E9 }
    condition:
        $a at pe.entry_point

}
rule Crinkler_V03_V04_Rune_LHStubbe_and_Aske_Simon_Christensen_additional: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 }
    condition:
        $a at pe.entry_point

}
rule Crinkler_V01_V02_Rune_LHStubbe_and_Aske_Simon_Christensen_additional: PEiD
{
    strings:
        $a = { B8 EF BE AD DE 50 6A ?? FF 15 10 19 40 ?? E9 AD FF FF FF }
    condition:
        $a at pe.entry_point

}
rule Crinkler_V03_V04_Rune_LHStubbe_and_Aske_Simon_Christensen: PEiD
{
    strings:
        $a = { B8 00 00 42 00 31 DB 43 EB 58 }
    condition:
        $a at pe.entry_point

}

rule ASPack_v107b_DLL: PEiD
{
    strings:
        $a = { 90 90 90 75 }
        $b = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPAck_1061b: PEiD
{
    strings:
        $a = { 90 90 75 00 E9 }
    condition:
        $a at pe.entry_point

}
rule ASPack_108: PEiD
{
    strings:
        $a = { 90 90 90 75 01 90 E9 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v212_additional: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v2xx: PEiD
{
    strings:
        $a = { 60 E8 70 05 ?? ?? EB }
        $b = { A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v21_additional: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }
    condition:
        $a at pe.entry_point

}
rule ASPack_102b: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 2B 85 7D 7C 43 00 89 85 89 7C 43 00 80 BD 74 7C 43 00 00 75 15 FE 85 74 7C 43 00 E8 1D 00 00 00 E8 F7 01 00 00 E8 8E 02 00 00 8B 85 75 7C 43 00 03 85 89 7C 43 00 89 44 24 1C 61 FF }
    condition:
        $a at pe.entry_point

}
rule ASPack_v21: PEiD
{
    strings:
        $a = { 60 E9 3D }
        $b = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PackerAspack_v212_wwwaspackcom: PEiD
{
    strings:
        $a = { ?8 ?? ?0 00 ?? ?? ?? ?? ?D ?? ?? ?? ?? ?? ?? ?? ?? ?? 5? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?F ?? ?? ?3 ?? ?? ?? 8? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?F 95 ?? ?? ?? ?? 8? ?? ?D ?? ?? ?? ?? 5? }
    condition:
        $a at pe.entry_point

}
rule ASPack_v211c_additional: PEiD
{
    strings:
        $a = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v104b_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE ?? ?? 80 BD 01 DE }
    condition:
        $a at pe.entry_point

}
rule ASPack_105b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED CE 3A 44 00 B8 C8 3A 44 00 03 C5 2B 85 B5 3E 44 00 89 85 C1 3E 44 00 80 BD AC 3E 44 }
    condition:
        $a at pe.entry_point

}
rule Aspack_v212_wwwaspackcom_additional: PEiD
{
    strings:
        $a = { ?8 ?? ?0 00 ?? ?? ?? ?? ?D ?? ?? ?? ?? ?? ?? ?? ?? ?? 5? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?F ?? ?? ?3 ?? ?? ?? 8? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?F 95 ?? ?? ?? ?? 8? ?? ?D ?? ?? ?? ?? 5? }
    condition:
        $a at pe.entry_point

}
rule AHTeam_EP_Protector_03_fake_ASPack_212_FEUERRADER: PEiD
{
    strings:
        $a = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }
    condition:
        $a at pe.entry_point

}
rule ASPack_108_additional: PEiD
{
    strings:
        $a = { 90 90 90 75 01 90 E9 }
    condition:
        $a at pe.entry_point

}
rule MSLRH_v032a_fake_ASPack_211d_emadicius: PEiD
{
    strings:
        $a = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
    condition:
        $a at pe.entry_point

}
rule ASPack_v102a_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }
    condition:
        $a at pe.entry_point

}
rule ASPack_v2000_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 70 05 00 00 EB 4C }
    condition:
        $a at pe.entry_point

}
rule MSLRH_v032a_fake_ASPack_211d_emadicius_h: PEiD
{
    strings:
        $a = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
    condition:
        $a at pe.entry_point

}
rule ASPack_105b_by_Hint_WIN_EP: PEiD
{
    strings:
        $a = { 75 00 E9 }
    condition:
        $a at pe.entry_point

}
rule ASPack_1083: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E 44 00 0F 85 17 05 00 00 8D 85 D1 50 44 00 50 FF 95 94 51 44 00 89 85 CD 50 44 00 8B F8 8D 9D DE 50 44 00 53 50 FF 95 90 51 44 00 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v108_additional: PEiD
{
    strings:
        $a = { 90 75 01 FF E9 }
    condition:
        $a at pe.entry_point

}
rule ASPack_102a_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 3E D9 43 00 B8 38 ?? ?? 00 03 C5 2B 85 0B DE 43 00 89 85 17 DE 43 00 80 BD 01 DE 43 00 00 75 15 FE 85 01 DE 43 00 E8 1D 00 00 00 E8 79 02 00 00 E8 12 03 00 00 8B 85 03 DE 43 00 03 85 17 DE 43 00 89 44 24 1C 61 FF }
    condition:
        $a at pe.entry_point

}
rule ASPack_v106b_additional: PEiD
{
    strings:
        $a = { 90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
    condition:
        $a at pe.entry_point

}
rule ASPack_v211d_additional: PEiD
{
    strings:
        $a = { 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v212: PEiD
{
    strings:
        $a = { 60 E8 03 ?? ?? ?? E9 EB 04 5D 45 55 C3 E8 }
        $b = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v211: PEiD
{
    strings:
        $a = { 60 E8 02 ?? ?? ?? EB 09 5D 55 81 ED 39 39 44 ?? C3 E9 3D }
        $b = { 60 E9 3D 04 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule _PseudoSigner_01_ASPack_2xx_Heuristic_Anorganix: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }
    condition:
        $a at pe.entry_point

}
rule ASPack_101b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED D2 2A 44 00 B8 CC 2A 44 00 03 C5 2B 85 A5 2E 44 00 89 85 B1 2E 44 00 80 BD 9C 2E 44 }
    condition:
        $a at pe.entry_point

}
rule Aspack_v212_wwwaspackcom: PEiD
{
    strings:
        $a = { ?8 ?? ?0 00 ?? ?? ?? ?? ?D ?? ?? ?? ?? ?? ?? ?? ?? ?? 5? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?F ?? ?? ?3 ?? ?? ?? 8? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?F 95 ?? ?? ?? ?? 8? }
    condition:
        $a at pe.entry_point

}
rule ASPack_v2xx_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v2001_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 72 05 00 00 EB 4C }
    condition:
        $a at pe.entry_point

}
rule MSLRH_032a_fake_ASPack_212_emadicius: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 73 00 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B }
        $b = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 A0 02 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule _PseudoSigner_01_ASPack_2xx_Heuristic_Anorganix_additional: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v107b_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 60 E8 2B 03 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v100b_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }
    condition:
        $a at pe.entry_point

}
rule ASPack_v211c_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v211b_additional: PEiD
{
    strings:
        $a = { 60 E8 02 00 00 00 EB 09 5D 55 }
    condition:
        $a at pe.entry_point

}
rule ASPack_105b_by: PEiD
{
    strings:
        $a = { 75 00 E9 }
    condition:
        $a at pe.entry_point

}
rule MSLRH_v032a_fake_ASPack_212_emadicius_h_additional: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 A0 02 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
    condition:
        $a at pe.entry_point

}
rule ASPack_v10802_additional: PEiD
{
    strings:
        $a = { 90 75 01 90 E9 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v2001_additional: PEiD
{
    strings:
        $a = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v107b: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D B8 03 }
        $b = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE ?? ?? 80 BD 01 DE }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_100b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 92 1A 44 00 B8 8C 1A 44 00 03 C5 2B 85 CD 1D 44 00 89 85 D9 1D 44 00 80 BD C4 1D 44 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v101b_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v10801_additional: PEiD
{
    strings:
        $a = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v10802_Hint_WIN_EP: PEiD
{
    strings:
        $a = { 90 75 01 90 E9 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v2xx_additional: PEiD
{
    strings:
        $a = { A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v101b: PEiD
{
    strings:
        $a = { 60 E8 5D 81 ED 3E D9 43 B8 38 03 C5 2B 85 0B DE 43 89 85 17 DE 43 80 BD 01 DE 43 75 15 FE 85 01 DE 43 E8 1D E8 79 02 E8 12 03 8B }
        $b = { 60 E8 ?? ?? ?? ?? 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v10803_additional: PEiD
{
    strings:
        $a = { 55 57 51 53 E8 ?? ?? ?? ?? 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 09 89 85 ?? ?? ?? ?? 0F B6 }
    condition:
        $a at pe.entry_point

}
rule ASPack_104b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? 00 B8 ?? ?? ?? 00 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? 00 80 BD 08 9D ?? 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASPack_107b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 90 75 ?? E9 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v103b: PEiD
{
    strings:
        $a = { 60 E8 5D 81 ED CE 3A 44 B8 C8 3A 44 03 C5 2B 85 B5 3E 44 89 85 C1 3E 44 80 BD AC 3E }
        $b = { 60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_102b_or_10803: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED }
    condition:
        $a at pe.entry_point

}
rule ASPack_v211d: PEiD
{
    strings:
        $a = { 60 E8 03 ?? ?? ?? E9 EB 04 5D 45 55 C3 E8 01 ?? ?? ?? EB 5D BB ED FF FF FF 03 DD 81 }
        $b = { 60 E8 02 00 00 00 EB 09 5D 55 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v211b: PEiD
{
    strings:
        $a = { 60 E8 02 ?? ?? ?? EB 09 5D 55 81 ED 39 39 44 ?? C3 E9 59 }
        $b = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v211c: PEiD
{
    strings:
        $a = { 60 E8 02 ?? ?? ?? EB 09 5D }
        $b = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v105b_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }
    condition:
        $a at pe.entry_point

}
rule MSLRH_032a_fake_ASPack_212_emadicius_additional: PEiD
{
    strings:
        $a = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v102b_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }
    condition:
        $a at pe.entry_point

}
rule ASPack_108_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 90 75 01 FF E9 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v1061b_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v102a_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23 }
    condition:
        $a at pe.entry_point

}
rule ASPack_2xwithouth_Poly_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { ?? 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB EC FF FF FF 03 DD 81 EB 00 40 1C 00 }
    condition:
        $a at pe.entry_point

}
rule ASPack_1061b_DLL: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED EA A8 43 00 B8 E4 A8 43 00 03 C5 2B 85 78 AD 43 00 89 85 84 AD 43 00 80 BD 6E AD 43 00 00 75 15 FE 85 6E AD 43 00 E8 1D 00 00 00 E8 73 02 00 00 E8 0A 03 00 00 8B 85 70 AD 43 00 03 85 84 AD 43 00 89 44 24 1C 61 FF }
    condition:
        $a at pe.entry_point

}
rule ASPack_v10804: PEiD
{
    strings:
        $a = { A8 03 61 75 08 B8 01 C2 0C 68 C3 8B 85 26 04 8D 8D 3B 04 51 50 FF }
        $b = { 60 E8 41 06 00 00 EB 41 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v100b_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v10804_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? EB }
    condition:
        $a at pe.entry_point

}
rule ASPack_10801_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 90 75 ?? 90 E9 }
    condition:
        $a at pe.entry_point

}
rule ASPack_101b: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED D2 2A 44 00 B8 CC 2A 44 00 03 C5 2B 85 A5 2E 44 00 89 85 B1 2E 44 00 80 BD 9C 2E 44 00 00 75 15 FE 85 9C 2E 44 00 E8 1D 00 00 00 E8 E4 01 00 00 E8 7A 02 00 00 8B 85 9D 2E 44 00 03 85 B1 2E 44 00 89 44 24 1C 61 FF }
    condition:
        $a at pe.entry_point

}
rule ASPack_v10804_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 41 06 00 00 EB 41 }
    condition:
        $a at pe.entry_point

}
rule ASPack_103b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED AE 98 43 00 B8 A8 98 43 00 03 C5 2B 85 18 9D 43 00 89 85 24 9D 43 00 80 BD 0E 9D 43 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v103b_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }
    condition:
        $a at pe.entry_point

}
rule MSLRH_v032a_fake_ASPack_212_emadicius_h: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 73 00 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v101b_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v10802_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72 }
    condition:
        $a at pe.entry_point

}
rule ASPack_105b: PEiD
{
    strings:
        $a = { 75 00 E9 }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_01_ASPack_2xx_Heuristic: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }
    condition:
        $a at pe.entry_point

}
rule MSLRH_v032a_fake_ASPack_212_emadicius: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 A0 02 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
        $b = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 73 00 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_1061b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED EA A8 43 00 B8 E4 A8 43 00 03 C5 2B 85 78 AD 43 00 89 85 84 AD 43 00 80 BD 6E AD 43 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v21_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v2000_additional: PEiD
{
    strings:
        $a = { 60 E8 48 11 00 00 C3 83 }
    condition:
        $a at pe.entry_point

}
rule ASPack_106b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 90 75 00 E9 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v10804_Hint_WIN_EP: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? EB }
    condition:
        $a at pe.entry_point

}
rule ASPack_v2000: PEiD
{
    strings:
        $a = { 60 E8 72 05 ?? ?? EB }
        $b = { 60 E8 70 05 00 00 EB 4C }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v2001: PEiD
{
    strings:
        $a = { 60 E8 72 05 ?? ?? EB 33 87 DB }
        $b = { 60 E8 72 05 00 00 EB 4C }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule MSLRH_032a_fake_ASPack_211d_emadicius: PEiD
{
    strings:
        $a = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v103b_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? E8 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v211d_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 02 00 00 00 EB 09 5D 55 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v108x: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D BB 03 }
        $b = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v1061b: PEiD
{
    strings:
        $a = { 60 E8 5D 81 ED B8 03 C5 2B 85 0B DE 89 85 17 DE 80 BD 01 }
        $b = { 60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v10801: PEiD
{
    strings:
        $a = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 44 BB 10 44 03 DD 2B }
        $b = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v10802: PEiD
{
    strings:
        $a = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 ?? BB 10 6A 44 ?? 03 DD 2B 9D }
        $b = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v10803: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 4A 44 ?? BB 04 4A 44 ?? 03 }
        $b = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_107b_DLL: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 3E D9 43 00 B8 38 D9 43 00 03 C5 2B 85 0B DE 43 00 89 85 17 DE 43 00 80 BD 01 DE 43 00 00 75 15 FE 85 01 DE 43 00 E8 1D 00 00 00 E8 79 02 00 00 E8 12 03 00 00 8B 85 03 DE 43 00 03 85 17 DE 43 00 89 44 24 1C 61 FF }
    condition:
        $a at pe.entry_point

}
rule ASPack_v107b_DLL_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_ASPack_2xx_Heuristic: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v211_additional: PEiD
{
    strings:
        $a = { 60 E8 F9 11 00 00 C3 83 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v10802_Hint_WIN_EP_additional: PEiD
{
    strings:
        $a = { 90 90 75 01 90 E9 }
    condition:
        $a at pe.entry_point

}
rule ASPack_212withouth_Poly_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { ?? E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v10803_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD }
    condition:
        $a at pe.entry_point

}
rule ASPack_v212_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v104b: PEiD
{
    strings:
        $a = { 75 ?? }
        $b = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? ?? 80 BD 08 9D }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v105b: PEiD
{
    strings:
        $a = { 90 75 ?? }
        $b = { 60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule MSLRH_032a_fake_ASPack_211d_emadicius_additional: PEiD
{
    strings:
        $a = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 EB 02 C7 05 EB 02 CD 20 E8 03 00 00 00 E9 EB 04 58 40 50 C3 61 9D 1F EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v108: PEiD
{
    strings:
        $a = { 90 90 75 01 FF }
        $b = { 90 75 01 FF E9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule MSLRH_v032a_fake_ASPack_212_emadicius_additional: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 A0 02 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
    condition:
        $a at pe.entry_point

}
rule ASPack_v102b_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 8A 1C 40 00 B9 9E 00 00 00 8D BD 4C 23 40 00 8B F7 33 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v106b: PEiD
{
    strings:
        $a = { 90 90 75 ?? }
        $b = { 90 90 90 75 00 E9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v104b_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? ?? 80 BD 08 9D }
    condition:
        $a at pe.entry_point

}
rule ASPack_V22_Alexey_Solodovnikov_StarForce_2009408: PEiD
{
    strings:
        $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD ?? ?? ?? ?? ?? ?? 83 BD 7D 04 00 00 00 89 9D 7D 04 00 00 0F 85 C0 03 00 00 8D 85 89 04 00 00 50 FF 95 09 0F 00 00 89 85 81 04 00 00 8B F0 8D 7D 51 57 56 FF 95 05 0F 00 00 AB B0 00 AE 75 FD 38 07 75 EE 8D 45 7A FF E0 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 56 69 72 74 75 61 6C 46 72 65 65 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 8B 9D 8D 05 00 00 0B DB 74 0A 8B 03 87 85 91 05 00 00 89 03 8D B5 BD 05 00 00 83 3E 00 0F 84 15 01 00 00 6A 04 68 00 10 00 00 68 00 18 00 00 6A 00 FF 55 51 89 85 53 01 00 00 8B 46 04 05 0E 01 00 00 6A 04 68 00 10 00 00 50 6A 00 FF 55 51 89 85 4F 01 00 00 56 8B 1E 03 9D 7D 04 00 00 FF B5 53 01 00 00 FF 76 04 50 53 E8 2D 05 00 00 B3 00 80 FB 00 75 5E FE 85 E9 00 00 00 8B 3E 03 BD 7D 04 00 00 FF 37 C6 07 C3 FF D7 8F 07 50 51 56 53 8B C8 83 E9 06 8B B5 4F 01 00 00 33 DB 0B C9 74 2E 78 2C AC 3C E8 74 0A EB 00 3C E9 74 04 43 49 EB EB 8B 06 EB 00 ?? ?? ?? 75 F3 24 00 C1 C0 18 2B C3 89 06 83 C3 05 83 C6 04 83 E9 05 EB CE 5B 5E 59 58 EB 08 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v107b_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE ?? ?? 80 BD 01 DE }
    condition:
        $a at pe.entry_point

}
rule ASPack_v108x_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A }
    condition:
        $a at pe.entry_point

}
rule ASPack_v10801_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D }
        $b = { 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v100b: PEiD
{
    strings:
        $a = { 60 E8 5D 81 ED D2 2A 44 B8 CC 2A 44 03 C5 2B 85 A5 2E 44 89 85 B1 2E 44 80 BD 9C 2E }
        $b = { 60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_102b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 2B 85 7D 7C 43 00 89 85 89 7C 43 00 80 BD 74 7C 43 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v102a: PEiD
{
    strings:
        $a = { 60 E8 5D 81 ED 96 78 43 B8 90 78 43 03 C5 2B 85 7D 7C 43 89 85 89 7C 43 80 BD 74 7C }
        $b = { 60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v102b: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 }
        $b = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ASPack_v108x_additional: PEiD
{
    strings:
        $a = { 60 E9 ?? ?? ?? ?? EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }
    condition:
        $a at pe.entry_point

}
rule ASPack_v211b_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v105b_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }
    condition:
        $a at pe.entry_point

}
rule ASPack_211_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E9 3D 04 00 00 }
    condition:
        $a at pe.entry_point

}
rule ASPack_212b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { ?? 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB EC FF FF FF 03 DD 81 EB 00 ?? ?? 00 83 BD 22 04 00 00 00 89 9D 22 04 00 00 0F 85 65 03 00 00 8D 85 2E 04 00 00 50 FF 95 4C 0F 00 00 89 85 26 04 00 00 8B F8 8D 5D 5E 53 50 FF 95 48 0F 00 00 89 85 4C 05 00 00 8D 5D 6B 53 57 FF 95 48 0F }
    condition:
        $a at pe.entry_point

}
rule ASPack_v1061b_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }
    condition:
        $a at pe.entry_point

}
rule ASPack_v107b_DLL_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }
    condition:
        $a at pe.entry_point

}

rule VMProtect_v125_PolyTech_additional: PEiD
{
    strings:
        $a = { 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
    condition:
        $a at pe.entry_point

}
rule VMProtect246_PolyTech: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 60 C7 ?? ?? ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 60 E8 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_v125_PolyTech: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 52 }
        $b = { 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
        $c = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule VMProtect_07x_08_PolyTech_additional: PEiD
{
    strings:
        $a = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D }
    condition:
        $a at pe.entry_point

}
rule VMProtect_106107_PolyTech_additional: PEiD
{
    strings:
        $a = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_V1X_PolyTech: PEiD
{
    strings:
        $a = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_0x_PolyTech: PEiD
{
    strings:
        $a = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_180_phpbb3: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? A8 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_V1X_PolyTech_additional: PEiD
{
    strings:
        $a = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_1704_phpbb3: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_0x_PolyTech_additional: PEiD
{
    strings:
        $a = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_106107_PolyTech: PEiD
{
    strings:
        $a = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_07x_08_PolyTech: PEiD
{
    strings:
        $a = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D }
    condition:
        $a at pe.entry_point

}
rule _VMProtect_v125_PolyTech_additional: PEiD
{
    strings:
        $a = { 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
    condition:
        $a at pe.entry_point

}
rule _VMProtect_v125_PolyTech: PEiD
{
    strings:
        $a = { 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
        $b = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 56 52 56 51 9C 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 A7 72 45 00 C3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}

rule FSG_v110_Eng_dulekxt_Borland_Cpp_1999_additional: PEiD
{
    strings:
        $a = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_70_ASM: PEiD
{
    strings:
        $a = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8 }
    condition:
        $a at pe.entry_point

}
rule FSG_120_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp: PEiD
{
    strings:
        $a = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_FSG_10_Anorganix: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B E9 }
    condition:
        $a at pe.entry_point

}
rule FSG_v131: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9 }
    condition:
        $a at pe.entry_point

}
rule FSG_v133: PEiD
{
    strings:
        $a = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }
    condition:
        $a at pe.entry_point

}
rule FSG_v10_additional: PEiD
{
    strings:
        $a = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA 33 0F B6 C9 0F BE 0E 88 16 EB 01 5F EB 01 6B 46 EB 01 6D 0F BE C0 4B EB 02 CD 20 0F BE C9 2B C9 3B D9 75 B0 EB 01 99 C1 C1 05 91 9D B2 E3 22 E2 A1 E2 F2 22 E2 A0 ?? ?? ?? E2 35 CA EC E2 E2 E2 E4 B4 57 E7 6C F8 28 F4 B4 A5 94 62 15 BD 86 95 E4 E1 F6 06 55 DA 15 AB E1 F6 06 55 FA 15 A2 E1 F6 06 55 03 95 E4 23 92 F2 E1 F6 06 F4 A2 55 DB 57 21 8C CD BE CA 25 E2 E2 E2 0D AD 57 F2 CA 1A E2 E2 E2 CD 0A 8E B3 CA 56 23 F5 AB CD FE 73 2A A3 C2 EA 8E CA 04 E2 E2 E2 1F E2 5F E2 E2 55 EC 62 DE E7 55 E8 65 DA 61 59 E4 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_bartxt_WinRAR_SFX_additional: PEiD
{
    strings:
        $a = { EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cue_60: PEiD
{
    strings:
        $a = { EB 02 CD 20 ?? CF ?? ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_131_Eng_dulekxt: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB }
        $b = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Borland_Cpp_: PEiD
{
    strings:
        $a = { EB 01 2E EB 02 A5 55 BB 80 ?? ?? 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }
    condition:
        $a at pe.entry_point

}
rule FSG_v120_Eng_dulekxt_Microsoft_Visual_Cpp_60_70: PEiD
{
    strings:
        $a = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA }
        $b = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA 73 8B CF 81 C2 96 44 EB 04 EB 02 CD 20 88 16 E8 02 00 00 00 44 A2 59 46 E8 01 00 00 00 AD 59 4B 80 C1 13 83 FB 00 75 B2 F7 D9 96 8F 80 4D 0C 4C 91 50 1C 0C 50 8A ?? ?? ?? 50 E9 34 16 50 4C 4C 0E 7E 9B 49 C6 32 02 3E 7E 7B 5E 8C C5 6B 50 3F 0E 0F 38 C8 95 18 D1 65 11 2C B8 87 28 C3 4C 0B 3C AC D9 2D 15 4E 8F 1C 40 4F 28 98 3E 10 C1 45 DB 8F 06 3F EC 48 61 4C 50 50 81 DF C3 20 34 84 10 10 0C 1F 68 DC FF 24 8C 4D 29 F5 1D 2C BF 74 CF F0 24 C0 08 2E 0C 0C 10 51 0C 91 10 10 81 16 D0 54 4B D7 42 C3 54 CB C9 4E }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v130_Eng_dulekxt: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }
        $b = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? 00 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE 0F 75 06 47 FF 37 AF EB 09 FE 0F 0F 84 ?? ?? ?? FF 57 55 FF 53 04 09 06 AD 75 DB 8B EC C3 ?? ?? ?? 00 00 00 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_70_additional: PEiD
{
    strings:
        $a = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Cpp_1999_: PEiD
{
    strings:
        $a = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_bartxt: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }
        $b = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB 27 ?? ?? 00 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 07 74 EF FE 07 75 06 47 FF 37 AF EB 09 FE 07 0F 84 1A ?? ?? FF 57 55 FF 53 04 09 06 AD 75 DB 8B EC C3 1B ?? ?? 00 00 00 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PseudoSigner_02_FSG_10: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_50_60_: PEiD
{
    strings:
        $a = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }
    condition:
        $a at pe.entry_point

}
rule FSG_120_Eng_dulekxt_Microsoft_Visual_Cpp_60_70_additional: PEiD
{
    strings:
        $a = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_02_FSG_10_Anorganix: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }
    condition:
        $a at pe.entry_point

}
rule FSG_120_Eng_dulekxt_Borland_Cpp: PEiD
{
    strings:
        $a = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE }
        $b = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v133a_dulekxt: PEiD
{
    strings:
        $a = { BE A8 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_: PEiD
{
    strings:
        $a = { 91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 ?? ?? 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp: PEiD
{
    strings:
        $a = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
        $b = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 D6 83 C7 32 F7 DA 03 FE EB 02 CD 20 87 FA 88 10 EB 02 CD 20 40 E8 02 00 00 00 F1 F8 5B 4E 2B D2 85 F6 75 AF EB 02 DE 09 EB 01 EF 34 4A 7C BC 7D 3D 7F 90 C1 82 41 ?? ?? ?? 87 DB 71 94 8B 8C 8D 90 61 05 96 1C A9 DA A7 68 5A 4A 19 CD 76 40 50 A0 9E B4 C5 15 9B D7 6E A5 BB CC 1C C2 DE 6C AC C2 D3 23 D2 65 B5 F5 65 C6 B6 CC DD CC 7B 2F B6 33 FE 6A AC 9E AB 07 C5 C6 C7 F3 94 3F DB B4 05 CE CF D0 BC FA 7F A5 BD 4A 18 EB A2 C5 F7 6D 25 9F BF E8 8D CA 05 E4 E5 E6 24 E8 66 EA EB 5F F7 6E EB F5 64 F8 76 EC 74 6D F9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v133_Eng_dulekxt: PEiD
{
    strings:
        $a = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Basic_50_60_additional: PEiD
{
    strings:
        $a = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Basic_50_60: PEiD
{
    strings:
        $a = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77 }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_01_FSG_10_Anorganix: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B E9 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Basic_50_60_: PEiD
{
    strings:
        $a = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77 }
    condition:
        $a at pe.entry_point

}
rule FSG_120_Eng_dulekxt_Microsoft_Visual_Cpp_60_70: PEiD
{
    strings:
        $a = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA }
    condition:
        $a at pe.entry_point

}
rule FSG_120_Eng_dulekxt_Borland_Delphi_Borland_Cpp_additional: PEiD
{
    strings:
        $a = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_40_50_: PEiD
{
    strings:
        $a = { EB 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 }
    condition:
        $a at pe.entry_point

}
rule FSG_v11_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_additional: PEiD
{
    strings:
        $a = { F7 D9 80 E1 FE 75 02 49 49 97 A3 ?? ?? 03 C1 24 FE 75 02 48 }
    condition:
        $a at pe.entry_point

}
rule FSG_13_additional: PEiD
{
    strings:
        $a = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D }
    condition:
        $a at pe.entry_point

}
rule FSG_120_Eng_dulekxt_Microsoft_Visual_Cpp_60_additional: PEiD
{
    strings:
        $a = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_MASM32_TASM32_Microsoft_Visual_Basic: PEiD
{
    strings:
        $a = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_MS_Visual_Cpp_Borland_Cpp_Watcom_Cpp: PEiD
{
    strings:
        $a = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_dulekxt_Microsoft_Visual_Cpp_70: PEiD
{
    strings:
        $a = { EB 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_50_60_additional: PEiD
{
    strings:
        $a = { 8D 50 12 2B C9 B1 1E 8A 02 34 77 88 02 42 E2 F7 C8 8C }
    condition:
        $a at pe.entry_point

}
rule FSG_v13: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }
        $b = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? ?? 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE ?? 74 EF FE }
        $c = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? ?? 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v12: PEiD
{
    strings:
        $a = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 ?? 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_v11: PEiD
{
    strings:
        $a = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 }
    condition:
        $a at pe.entry_point

}
rule FSG_v10: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_70_ASM_: PEiD
{
    strings:
        $a = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_bartxt_WinRAR_SFX: PEiD
{
    strings:
        $a = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_20_: PEiD
{
    strings:
        $a = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }
    condition:
        $a at pe.entry_point

}
rule SkD_Undetectabler_3_No_FSG_2_Method_SkD_additional: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC 10 02 00 00 68 00 02 00 00 8D 85 F8 FD FF FF 50 6A 00 FF 15 38 10 00 01 50 FF 15 3C 10 00 01 8D 8D F8 FD FF FF 51 E8 4F FB FF FF 83 C4 04 8B 15 ?? 16 00 01 52 A1 ?? 16 00 01 50 E8 50 FF FF FF 83 C4 08 A3 ?? 16 00 01 C7 85 F4 FD FF FF 00 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_v20_additional: PEiD
{
    strings:
        $a = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 }
    condition:
        $a at pe.entry_point

}
rule FSG_v120_Eng_dulekxt_Microsoft_Visual_Cpp_60_additional: PEiD
{
    strings:
        $a = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 EB 02 42 C0 EB 01 08 88 16 80 F1 98 80 C9 28 46 91 EB 02 C0 55 4B EB 01 55 34 44 0B DB 75 AD E8 01 00 00 00 9D 59 0B C6 EB 01 6C E9 D2 C3 82 C2 03 C2 B2 82 C2 00 ?? ?? 7C C2 6F DA BC C2 C2 C2 CC 1C 3D CF 4C D8 84 D0 0C FD F0 42 77 0D 66 F1 AC C1 DE CE 97 BA D7 EB C3 AE DE 91 AA D5 02 0D 1E EE 3F 23 77 C4 01 72 12 C1 0E 1E 14 82 37 AB 39 01 88 C9 DE CA 07 C2 C2 C2 17 79 49 B2 DA 0A C2 C2 C2 A9 EA 6E 91 AA 2E 03 CF 7B 9F CE 51 FA 6D A2 AA 56 8A E4 C2 C2 C2 07 C2 47 C2 C2 17 B8 42 C6 8D 31 88 45 BA 3D 2B BC }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_MASM32_: PEiD
{
    strings:
        $a = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }
    condition:
        $a at pe.entry_point

}
rule FSG_131_dulekxt_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_02_FSG_131_Anorganix: PEiD
{
    strings:
        $a = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Cue: PEiD
{
    strings:
        $a = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB }
    condition:
        $a at pe.entry_point

}
rule FSG_120_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp_additional: PEiD
{
    strings:
        $a = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_bartxt_Watcom_CCpp_EXE_: PEiD
{
    strings:
        $a = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }
    condition:
        $a at pe.entry_point

}
rule FSG_v12_additional: PEiD
{
    strings:
        $a = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 ?? 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_dulekxt_Microsoft_Visual_Cpp_60_70: PEiD
{
    strings:
        $a = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Cpp_1999: PEiD
{
    strings:
        $a = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_MASM32_TASM32_Microsoft_Visual_Basic_: PEiD
{
    strings:
        $a = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }
    condition:
        $a at pe.entry_point

}
rule FSG_v120_Eng_dulekxt_Borland_Delphi_Borland_Cpp: PEiD
{
    strings:
        $a = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB }
        $b = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB EE 90 14 2C 77 2A D3 EB 01 87 2A D3 E8 01 00 00 00 92 59 88 16 EB 02 52 08 46 EB 02 CD 20 4B 80 F1 C2 85 DB 75 AE C1 E0 04 EB 00 DA B2 82 5C 9B C7 89 98 4F 8A F7 ?? ?? ?? B1 4D DF B8 AD AC AB D4 07 27 D4 50 CF 9A D5 1C EC F2 27 77 18 40 4E A4 A8 B4 CB 9F 1D D9 EC 1F AD BC 82 AA C0 4C 0A A2 15 45 18 8F BB 07 93 BE C0 BC A3 B0 9D 51 D4 F1 08 22 62 96 6D 09 73 7E 71 A5 3A E5 7D 94 A3 96 99 98 72 B2 31 57 7B FA AE 9D 28 4F 99 EF A3 25 49 60 03 42 8B 54 53 5E 92 50 D4 52 4D C1 55 76 FD F7 8A FC 78 0C 82 87 0F }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_V130Eng_dulekxt: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? 00 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE 0F 75 06 47 FF 37 AF EB 09 FE 0F 0F 84 ?? ?? ?? FF 57 55 FF 53 04 09 06 AD 75 DB 8B EC C3 ?? ?? ?? 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_110_Eng_dulekxt_Borland_Cpp: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }
        $b = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp_ASM_: PEiD
{
    strings:
        $a = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4 }
    condition:
        $a at pe.entry_point

}
rule FSG_110_Eng_dulekxt_Microsoft_Visual_Cpp_60: PEiD
{
    strings:
        $a = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }
        $b = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v120_Eng_dulekxt_MASM32_TASM32_additional: PEiD
{
    strings:
        $a = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE 58 80 EA 33 C1 E1 12 32 D3 48 80 C2 26 EB 02 CD 20 88 16 F7 D8 46 EB 01 C0 4B 40 8D 0D 00 00 00 00 3B D9 75 B7 EB 01 14 EB 01 0A CF C5 93 53 90 DA 96 67 54 8D CC ?? ?? 51 8E 18 74 53 82 83 80 47 B4 D2 41 FB 64 31 6A AF 7D 89 BC 0A 91 D7 83 37 39 43 50 A2 32 DC 81 32 3A 4B 97 3D D9 63 1F 55 42 F0 45 32 60 9A 28 51 61 4B 38 4B 12 E4 49 C4 99 09 47 F9 42 8C 48 51 4E 70 CF B8 12 2B 78 09 06 07 17 55 D6 EA 10 8D 3F 28 E5 02 0E A2 58 B8 D6 0F A8 E5 10 EB E8 F1 23 EF 61 E5 E2 54 EA A9 2A 22 AF 17 A1 23 97 9A 1C }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Borland_Cpp: PEiD
{
    strings:
        $a = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 }
    condition:
        $a at pe.entry_point

}
rule FSG_110_Eng_dulekxt_MASM32_TASM32: PEiD
{
    strings:
        $a = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
        $b = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_ASM: PEiD
{
    strings:
        $a = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Basic_MASM32_: PEiD
{
    strings:
        $a = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Borland_Cpp_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_40_50: PEiD
{
    strings:
        $a = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }
        $b = { EB 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v130_Eng_dulekxt_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? 00 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE 0F 75 06 47 FF 37 AF EB 09 FE 0F 0F 84 ?? ?? ?? FF 57 55 FF 53 04 09 06 AD 75 DB 8B EC C3 ?? ?? ?? 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Basic_MASM32_additional: PEiD
{
    strings:
        $a = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_FSG_10_Anorganix_additional: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B E9 }
    condition:
        $a at pe.entry_point

}
rule FSG_110_Eng_bartxt: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }
        $b = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v13_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9 }
    condition:
        $a at pe.entry_point

}
rule FSG_120_Eng_dulekxt_Borland_Cpp_additional: PEiD
{
    strings:
        $a = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cppx_additional: PEiD
{
    strings:
        $a = { CD 20 B8 03 00 CD 10 51 E8 00 00 5E 83 EE 09 }
    condition:
        $a at pe.entry_point

}
rule SkD_Undetectabler_3_No_FSG_2_Method_SkD: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC 10 02 00 00 68 00 02 00 00 8D 85 F8 FD FF FF 50 6A 00 FF 15 38 10 00 01 50 FF 15 3C 10 00 01 8D 8D F8 FD FF FF 51 E8 4F FB FF FF 83 C4 04 8B 15 ?? 16 00 01 52 A1 ?? 16 00 01 50 E8 50 FF FF FF 83 C4 08 A3 ?? 16 00 01 C7 85 F4 FD FF FF 00 00 00 00 EB 0F 8B 8D F4 FD FF FF 83 C1 01 89 8D F4 FD FF FF 8B 95 F4 FD FF FF 3B 15 ?? 16 00 01 73 1C 8B 85 F4 FD FF FF 8B 0D ?? 16 00 01 8D 54 01 07 81 FA 74 10 00 01 75 02 EB 02 EB C7 8B 85 F4 FD FF FF 50 E8 ?? 00 00 00 83 C4 04 89 85 F0 FD FF FF 8B 8D F0 FD FF FF 89 4D FC C7 45 F8 00 00 00 00 EB 09 8B 55 F8 83 C2 01 89 55 F8 8B 45 F8 3B 85 F4 FD FF FF 73 15 8B 4D FC 03 4D F8 8B 15 ?? 16 00 01 03 55 F8 8A 02 88 01 EB D7 83 3D ?? 16 00 01 00 74 }
        $b = { 55 8B EC 81 EC 10 02 00 00 68 00 02 00 00 8D 85 F8 FD FF FF 50 6A 00 FF 15 38 10 00 01 50 FF 15 3C 10 00 01 8D 8D F8 FD FF FF 51 E8 4F FB FF FF 83 C4 04 8B 15 ?? 16 00 01 52 A1 ?? 16 00 01 50 E8 50 FF FF FF 83 C4 08 A3 ?? 16 00 01 C7 85 F4 FD FF FF 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_70: PEiD
{
    strings:
        $a = { EB 01 }
        $b = { EB 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_20_additional: PEiD
{
    strings:
        $a = { EB 01 4D 83 F6 4C 68 80 ?? ?? 00 EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38 }
    condition:
        $a at pe.entry_point

}
rule FSG_v120_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp_additional: PEiD
{
    strings:
        $a = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 F7 2B FE EB 01 7F 81 EF DF 30 90 1E EB 02 CD 20 87 FA 88 10 80 EA 03 40 EB 01 20 4E EB 01 3D 83 FE 00 75 A2 EB 02 CD 20 EB 01 C3 78 73 42 F7 35 6C 2D 3F ED 33 97 ?? ?? ?? 5D F0 45 29 55 57 55 71 63 02 72 E9 1F 2D 67 B1 C0 91 FD 10 58 A3 90 71 6C 83 11 E0 5D 20 AE 5C 71 83 D0 7B 10 97 54 17 11 C0 0E 00 33 76 85 33 3C 33 21 31 F5 50 CE 56 6C 89 C8 F7 CD 70 D5 E3 DD 08 E8 4E 25 FF 0D F3 ED EF C8 0B 89 A6 CD 77 42 F0 A6 C8 19 66 3D B2 CD E7 89 CB 13 D7 D5 E3 1E DF 5A E3 D5 50 DF B3 39 32 C0 2D B0 3F B4 B4 43 }
    condition:
        $a at pe.entry_point

}
rule FSG_v120_Eng_dulekxt_Microsoft_Visual_Cpp_60_70_additional: PEiD
{
    strings:
        $a = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA 73 8B CF 81 C2 96 44 EB 04 EB 02 CD 20 88 16 E8 02 00 00 00 44 A2 59 46 E8 01 00 00 00 AD 59 4B 80 C1 13 83 FB 00 75 B2 F7 D9 96 8F 80 4D 0C 4C 91 50 1C 0C 50 8A ?? ?? ?? 50 E9 34 16 50 4C 4C 0E 7E 9B 49 C6 32 02 3E 7E 7B 5E 8C C5 6B 50 3F 0E 0F 38 C8 95 18 D1 65 11 2C B8 87 28 C3 4C 0B 3C AC D9 2D 15 4E 8F 1C 40 4F 28 98 3E 10 C1 45 DB 8F 06 3F EC 48 61 4C 50 50 81 DF C3 20 34 84 10 10 0C 1F 68 DC FF 24 8C 4D 29 F5 1D 2C BF 74 CF F0 24 C0 08 2E 0C 0C 10 51 0C 91 10 10 81 16 D0 54 4B D7 42 C3 54 CB C9 4E }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_50_60: PEiD
{
    strings:
        $a = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_bartxt_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 97 33 C9 41 FF D3 13 C9 FF D3 72 F8 C3 02 D2 75 05 8A 16 46 12 D2 C3 5B 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 58 FF FF FF 5F BB ?? ?? ?? 00 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE 0F 75 06 47 FF 37 AF EB 09 FE 0F 0F 84 ?? ?? ?? FF 57 55 FF 53 04 89 06 AD 85 C0 75 D9 8B EC C3 ?? ?? ?? 00 00 00 00 00 00 00 00 00 88 01 00 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_MASM32_TASM32: PEiD
{
    strings:
        $a = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cppx: PEiD
{
    strings:
        $a = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_120_Eng_dulekxt_MASM32_TASM32: PEiD
{
    strings:
        $a = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE }
        $b = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v131_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_4x_LCC_Win32_1x_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? 8E D8 B8 ?? ?? CD 21 A3 ?? ?? 3C 03 7D ?? B4 09 }
    condition:
        $a at pe.entry_point

}
rule FSG_v131_Eng_dulekxt_additional: PEiD
{
    strings:
        $a = { BB ?? ?? BA ?? ?? 81 C3 07 00 B8 40 B4 B1 04 D3 E8 03 C3 8C D9 49 8E C1 26 03 0E 03 00 2B }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? EB 02 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_02_FSG_131_Anorganix: PEiD
{
    strings:
        $a = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_MASM32_TASM32_Microsoft_Visual_Basic_additional: PEiD
{
    strings:
        $a = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68 }
    condition:
        $a at pe.entry_point

}
rule FSG_131_dulekxt_: PEiD
{
    strings:
        $a = { BE ?? ?? ?? 00 BF ?? ?? ?? 00 BB ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 }
    condition:
        $a at pe.entry_point

}
rule FSG_20_bartxt: PEiD
{
    strings:
        $a = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_: PEiD
{
    strings:
        $a = { EB ?? ?? ?? ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_110_Eng_bartxt_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 }
    condition:
        $a at pe.entry_point

}
rule FSG_131_dulekxt: PEiD
{
    strings:
        $a = { BE ?? ?? ?? 00 BF ?? ?? ?? 00 BB ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 }
        $b = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp: PEiD
{
    strings:
        $a = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
        $b = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp_ASM_additional: PEiD
{
    strings:
        $a = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA 73 8B CF 81 C2 96 44 EB 04 EB 02 CD 20 88 16 E8 02 00 00 00 44 A2 59 46 E8 01 00 00 00 AD 59 4B 80 C1 13 83 FB 00 75 B2 F7 D9 96 8F 80 4D 0C 4C 91 50 1C 0C 50 8A ?? ?? ?? 50 E9 34 16 50 4C 4C 0E 7E 9B 49 C6 32 02 3E 7E 7B 5E 8C C5 6B 50 3F 0E 0F 38 C8 95 18 D1 65 11 2C B8 87 28 C3 4C 0B 3C AC D9 2D 15 4E 8F 1C 40 4F 28 98 3E 10 C1 45 DB 8F 06 3F EC 48 61 4C 50 50 81 DF C3 20 34 84 10 10 0C 1F 68 DC FF 24 8C 4D 29 F5 1D 2C BF 74 CF F0 24 C0 08 2E 0C 0C 10 51 0C 91 10 10 81 16 D0 54 4B D7 42 C3 54 CB C9 4E }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_bartxt_Watcom_CCpp_EXE: PEiD
{
    strings:
        $a = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }
    condition:
        $a at pe.entry_point

}
rule FSG_100_Eng_dulekxt: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_MASM32_TASM32_additional: PEiD
{
    strings:
        $a = { EB 01 ?? EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 }
    condition:
        $a at pe.entry_point

}
rule FSG_v20_bartxt: PEiD
{
    strings:
        $a = { 87 25 ?? ?? ?? 00 61 94 55 A4 B6 80 FF 13 }
        $b = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? ?? 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE ?? 74 EF FE }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_V131Eng_dulekxt: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 97 33 C9 41 FF D3 13 C9 FF D3 72 F8 C3 02 D2 75 05 8A 16 46 12 D2 C3 5B 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 58 FF FF FF 5F BB ?? ?? ?? 00 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE 0F 75 06 47 FF 37 AF EB 09 FE 0F 0F 84 ?? ?? ?? FF 57 55 FF 53 04 89 06 AD 85 C0 75 D9 8B EC C3 ?? ?? ?? 00 00 00 00 00 00 00 00 00 88 01 00 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_v120_Eng_dulekxt_Microsoft_Visual_Cpp_60: PEiD
{
    strings:
        $a = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 }
        $b = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 EB 02 42 C0 EB 01 08 88 16 80 F1 98 80 C9 28 46 91 EB 02 C0 55 4B EB 01 55 34 44 0B DB 75 AD E8 01 00 00 00 9D 59 0B C6 EB 01 6C E9 D2 C3 82 C2 03 C2 B2 82 C2 00 ?? ?? 7C C2 6F DA BC C2 C2 C2 CC 1C 3D CF 4C D8 84 D0 0C FD F0 42 77 0D 66 F1 AC C1 DE CE 97 BA D7 EB C3 AE DE 91 AA D5 02 0D 1E EE 3F 23 77 C4 01 72 12 C1 0E 1E 14 82 37 AB 39 01 88 C9 DE CA 07 C2 C2 C2 17 79 49 B2 DA 0A C2 C2 C2 A9 EA 6E 91 AA 2E 03 CF 7B 9F CE 51 FA 6D A2 AA 56 8A E4 C2 C2 C2 07 C2 47 C2 C2 17 B8 42 C6 8D 31 88 45 BA 3D 2B BC }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_110_Eng_dulekxt_Borland_Delphi_Borland_Cpp_additional: PEiD
{
    strings:
        $a = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }
    condition:
        $a at pe.entry_point

}
rule FSG_v20_bartxt_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? ?? 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE ?? 74 EF FE }
    condition:
        $a at pe.entry_point

}
rule FSG_133_Eng_dulekxt: PEiD
{
    strings:
        $a = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_FSG_131_Anorganix: PEiD
{
    strings:
        $a = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9 }
    condition:
        $a at pe.entry_point

}
rule FSG_13: PEiD
{
    strings:
        $a = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D }
        $b = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp_additional: PEiD
{
    strings:
        $a = { 1E 0E 1F B8 ?? ?? 8E C0 26 8A 1E ?? ?? 80 ?? ?? 72 }
    condition:
        $a at pe.entry_point

}
rule FSG_120_Eng_dulekxt_MASM32_TASM32_additional: PEiD
{
    strings:
        $a = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 }
    condition:
        $a at pe.entry_point

}
rule FSG_v120_Eng_dulekxt_Borland_Cpp_additional: PEiD
{
    strings:
        $a = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 79 01 ?? ?? 59 EB 01 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_ASM_additional: PEiD
{
    strings:
        $a = { 03 05 00 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
    condition:
        $a at pe.entry_point

}
rule FSG_v100_Eng_dulekxt: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 }
        $b = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }
        $c = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 51 FF FF FF 5F BB 28 ?? ?? 00 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE 0F 75 06 47 FF 37 AF EB 09 FE 0F 0F 84 ?? ?? ?? FF 57 55 FF 53 04 09 06 AD 75 DB 8B EC C3 1C ?? ?? 00 00 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PseudoSigner_02_FSG_131: PEiD
{
    strings:
        $a = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 }
    condition:
        $a at pe.entry_point

}
rule FSG_120_Eng_dulekxt_Borland_Delphi_Borland_Cpp: PEiD
{
    strings:
        $a = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Basic_MASM32: PEiD
{
    strings:
        $a = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_01_FSG_131_Anorganix: PEiD
{
    strings:
        $a = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_02_FSG_10_Anorganix: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Cpp_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? ?? 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_02_FSG_10: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_FSG_131: PEiD
{
    strings:
        $a = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_70: PEiD
{
    strings:
        $a = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? 00 EB 02 CD 20 03 D3 8D 35 F4 00 00 00 EB 01 35 EB 01 88 80 CA 7C 80 F3 74 8B 38 EB 02 AC BA 03 DB E8 01 00 00 00 A5 5B C1 C2 0B 81 C7 DA 10 0A 4E EB 01 08 2B D1 83 EF 14 EB 02 CD 20 33 D3 83 EF 27 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_4x_LCC_Win32_1x: PEiD
{
    strings:
        $a = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_FSG_10: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B E9 }
    condition:
        $a at pe.entry_point

}
rule FSG_v20: PEiD
{
    strings:
        $a = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 }
        $b = { 87 25 ?? ?? ?? 00 61 94 55 A4 B6 80 FF 13 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_110_Eng_dulekxt_MASM32_TASM32_additional: PEiD
{
    strings:
        $a = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
    condition:
        $a at pe.entry_point

}
rule FSG_v120_Eng_dulekxt_MASM32_TASM32: PEiD
{
    strings:
        $a = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE }
        $b = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE 58 80 EA 33 C1 E1 12 32 D3 48 80 C2 26 EB 02 CD 20 88 16 F7 D8 46 EB 01 C0 4B 40 8D 0D 00 00 00 00 3B D9 75 B7 EB 01 14 EB 01 0A CF C5 93 53 90 DA 96 67 54 8D CC ?? ?? 51 8E 18 74 53 82 83 80 47 B4 D2 41 FB 64 31 6A AF 7D 89 BC 0A 91 D7 83 37 39 43 50 A2 32 DC 81 32 3A 4B 97 3D D9 63 1F 55 42 F0 45 32 60 9A 28 51 61 4B 38 4B 12 E4 49 C4 99 09 47 F9 42 8C 48 51 4E 70 CF B8 12 2B 78 09 06 07 17 55 D6 EA 10 8D 3F 28 E5 02 0E A2 58 B8 D6 0F A8 E5 10 EB E8 F1 23 EF 61 E5 E2 54 EA A9 2A 22 AF 17 A1 23 97 9A 1C }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v120_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp: PEiD
{
    strings:
        $a = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 }
        $b = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 F7 2B FE EB 01 7F 81 EF DF 30 90 1E EB 02 CD 20 87 FA 88 10 80 EA 03 40 EB 01 20 4E EB 01 3D 83 FE 00 75 A2 EB 02 CD 20 EB 01 C3 78 73 42 F7 35 6C 2D 3F ED 33 97 ?? ?? ?? 5D F0 45 29 55 57 55 71 63 02 72 E9 1F 2D 67 B1 C0 91 FD 10 58 A3 90 71 6C 83 11 E0 5D 20 AE 5C 71 83 D0 7B 10 97 54 17 11 C0 0E 00 33 76 85 33 3C 33 21 31 F5 50 CE 56 6C 89 C8 F7 CD 70 D5 E3 DD 08 E8 4E 25 FF 0D F3 ED EF C8 0B 89 A6 CD 77 42 F0 A6 C8 19 66 3D B2 CD E7 89 CB 13 D7 D5 E3 1E DF 5A E3 D5 50 DF B3 39 32 C0 2D B0 3F B4 B4 43 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_ASM_: PEiD
{
    strings:
        $a = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68 }
    condition:
        $a at pe.entry_point

}
rule FSG_v120_Eng_dulekxt_Borland_Delphi_Borland_Cpp_additional: PEiD
{
    strings:
        $a = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB EE 90 14 2C 77 2A D3 EB 01 87 2A D3 E8 01 00 00 00 92 59 88 16 EB 02 52 08 46 EB 02 CD 20 4B 80 F1 C2 85 DB 75 AE C1 E0 04 EB 00 DA B2 82 5C 9B C7 89 98 4F 8A F7 ?? ?? ?? B1 4D DF B8 AD AC AB D4 07 27 D4 50 CF 9A D5 1C EC F2 27 77 18 40 4E A4 A8 B4 CB 9F 1D D9 EC 1F AD BC 82 AA C0 4C 0A A2 15 45 18 8F BB 07 93 BE C0 BC A3 B0 9D 51 D4 F1 08 22 62 96 6D 09 73 7E 71 A5 3A E5 7D 94 A3 96 99 98 72 B2 31 57 7B FA AE 9D 28 4F 99 EF A3 25 49 60 03 42 8B 54 53 5E 92 50 D4 52 4D C1 55 76 FD F7 8A FC 78 0C 82 87 0F }
    condition:
        $a at pe.entry_point

}
rule FSG_v131_Eng_dulekxt: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB }
        $b = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 97 33 C9 41 FF D3 13 C9 FF D3 72 F8 C3 02 D2 75 05 8A 16 46 12 D2 C3 5B 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 58 FF FF FF 5F BB ?? ?? ?? 00 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE 0F 75 06 47 FF 37 AF EB 09 FE 0F 0F 84 ?? ?? ?? FF 57 55 FF 53 04 89 06 AD 85 C0 75 D9 8B EC C3 ?? ?? ?? 00 00 00 00 00 00 00 00 00 88 01 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_C_Basic_NET_: PEiD
{
    strings:
        $a = { EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 77 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B3 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_bartxt_Watcom_CCpp_EXE_additional: PEiD
{
    strings:
        $a = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_20: PEiD
{
    strings:
        $a = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_C_Basic_NET: PEiD
{
    strings:
        $a = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB }
        $b = { EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 77 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_131_Eng_dulekxt_additional: PEiD
{
    strings:
        $a = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 }
    condition:
        $a at pe.entry_point

}
rule FSG_v10_dulekxt: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_02_FSG_131: PEiD
{
    strings:
        $a = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_bartxt_WinRAR_SFX_: PEiD
{
    strings:
        $a = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0 }
    condition:
        $a at pe.entry_point

}
rule FSG_v133_Eng_dulekxt_additional: PEiD
{
    strings:
        $a = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 9D 8B D6 5E AD 48 74 0A 79 02 AD 50 56 8B F2 97 EB 87 AD 93 5E 46 AD 97 56 FF 13 95 AC 84 C0 75 FB FE 0E 74 F0 79 05 46 AD 50 EB 09 FE 0E 0F 84 ?? ?? ?? FF 56 55 FF 53 04 AB EB E0 33 C9 41 FF 13 13 C9 FF 13 72 F8 C3 02 D2 75 05 8A 16 46 12 D2 C3 ?? ?? ?? 00 00 00 00 00 00 00 00 00 54 01 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 61 01 00 00 6F 01 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_v133_dulekxt: PEiD
{
    strings:
        $a = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Cpp: PEiD
{
    strings:
        $a = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt: PEiD
{
    strings:
        $a = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }
    condition:
        $a at pe.entry_point

}
rule FSG_v100_Eng_dulekxt_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp_additional: PEiD
{
    strings:
        $a = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
    condition:
        $a at pe.entry_point

}
rule FSG_110_Eng_dulekxt_Borland_Delphi_Borland_Cpp: PEiD
{
    strings:
        $a = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }
        $b = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_70_: PEiD
{
    strings:
        $a = { EB 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB }
    condition:
        $a at pe.entry_point

}
rule FSG_v133_additional: PEiD
{
    strings:
        $a = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 9D 8B D6 5E AD 48 74 0A 79 02 AD 50 56 8B F2 97 EB 87 AD 93 5E 46 AD 97 56 FF 13 95 AC 84 C0 75 FB FE 0E 74 F0 79 05 46 AD 50 EB 09 FE 0E 0F 84 ?? ?? ?? FF 56 55 FF 53 04 AB EB E0 33 C9 41 FF 13 13 C9 FF 13 72 F8 C3 02 D2 75 05 8A 16 46 12 D2 C3 ?? ?? ?? 00 00 00 00 00 00 00 00 00 54 01 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 61 01 00 00 6F 01 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_4x_LCC_Win32_1x_: PEiD
{
    strings:
        $a = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp_: PEiD
{
    strings:
        $a = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp_ASM: PEiD
{
    strings:
        $a = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Borland_Cue: PEiD
{
    strings:
        $a = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_70_ASM_additional: PEiD
{
    strings:
        $a = { E8 01 00 00 00 0E 59 E8 01 00 00 00 58 58 BE 80 ?? ?? 00 EB 02 61 E9 68 F4 00 00 00 C1 C8 }
    condition:
        $a at pe.entry_point

}
rule FSG_120_Eng_dulekxt_Microsoft_Visual_Cpp_60: PEiD
{
    strings:
        $a = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 }
        $b = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_v110_Eng_dulekxt_MASM32_additional: PEiD
{
    strings:
        $a = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_MASM32: PEiD
{
    strings:
        $a = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_FSG_131_Anorganix_additional: PEiD
{
    strings:
        $a = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_dulekxt_Borland_Delphi_Borland_Cpp: PEiD
{
    strings:
        $a = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 EA 0F E8 01 00 00 00 64 59 02 D3 EB 02 D6 5C 88 16 EB 02 CD 20 46 E8 02 00 00 00 6B B5 59 4B 0F B7 C6 0B DB 75 B1 EB 02 50 AA 91 44 5C 90 D2 95 57 9B AE E1 A4 65 ?? ?? ?? B3 09 A1 C6 BF C2 C5 CA 9D 43 D6 5E ED 20 EF B2 A6 98 69 1F CA 96 A8 FA FA 12 25 77 F3 DD 60 F2 73 A8 C3 45 2E 22 43 C4 FA 15 2E 73 97 BE D5 04 25 A6 D5 E0 FC 54 EC D9 A0 84 C4 04 FA D6 D7 07 3A 14 4F 18 F6 AB D8 88 B8 E7 CB C4 36 B8 51 4E 4B 97 29 7C B4 3F D7 99 BC 66 DA CE 9C AC DD 01 0D 65 6D CD F5 5E F6 8E 7F 36 4F A7 AF 27 C7 70 5? }
    condition:
        $a at pe.entry_point

}
rule FSG_v120_Eng_dulekxt_Borland_Cpp: PEiD
{
    strings:
        $a = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 }
        $b = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 EB 02 56 7B 2A D3 E8 01 00 00 00 ED 58 88 16 13 C3 46 EB 02 CD 20 4B EB 02 CD 20 2B C9 3B D9 75 A1 E8 02 00 00 00 D7 6B 58 EB 00 9E 96 6A 28 67 AB 69 54 03 3E 7F ?? ?? ?? 31 0D 63 44 35 38 37 18 87 9F 10 8C 37 C6 41 80 4C 5E 8B DB 60 4C 3A 28 08 30 BF 93 05 D1 58 13 2D B8 86 AE C8 58 16 A6 95 C5 94 03 33 6F FF 92 20 98 87 9C E5 B9 20 B5 68 DE 16 4A 15 C1 7F 72 71 65 3E A9 85 20 AF 5A 59 54 26 66 E9 3F 27 DE 8E 7D 34 53 61 F7 AF 09 29 5C F7 36 83 60 5F 52 92 5C D0 56 55 C9 61 7A FD EF 7E E8 70 F8 6E 7B EF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule FSG_110_Eng_dulekxt_Microsoft_Visual_Cpp_60_additional: PEiD
{
    strings:
        $a = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60: PEiD
{
    strings:
        $a = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 }
    condition:
        $a at pe.entry_point

}
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_70_: PEiD
{
    strings:
        $a = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? ?? EB 02 CD 20 03 D3 8D 35 F4 00 }
    condition:
        $a at pe.entry_point

}
rule FSG_110_Eng_dulekxt_Borland_Cpp_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }
    condition:
        $a at pe.entry_point

}

rule Mew_11_SE_v12_Eng_Northfox_: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C }
    condition:
        $a at pe.entry_point

}
rule Mew_10_V10_Eng_Northfox: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? FF FF }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_v10_Northfox_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_12: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $b = { E9 ?? ?? ?? ?? 0C ?? ?? ?? 00 00 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule _PseudoSigner_02_MEW_11_SE_10_Anorganix: PEiD
{
    strings:
        $a = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_12_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 0C ?? ?? ?? 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_v11: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_v12: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $b = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule MEW_11_SE_11_Northfox_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 00 00 00 02 00 00 00 0C 00 }
    condition:
        $a at pe.entry_point

}
rule MEW_10_Northfox: PEiD
{
    strings:
        $a = { 33 C0 E9 }
    condition:
        $a at pe.entry_point

}
rule Mew_501_NorthFox_HCC: PEiD
{
    strings:
        $a = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 00 ?? ?? 00 ?? ?? ?? 00 00 10 40 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D }
        $b = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 00 ?? ?? 00 ?? ?? ?? 00 00 10 40 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule PseudoSigner_02_MEW_11_SE_10: PEiD
{
    strings:
        $a = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 }
    condition:
        $a at pe.entry_point

}
rule Mew_10_v10_Eng_Northfox: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? ?? FF }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_v12_NorthfoxHCC_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_11_Northfox: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 0C ?? ?? ?? 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Mew_11_SE_v12_Eng_Northfox: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C }
    condition:
        $a at pe.entry_point

}
rule MEW_10_packer_v10_Northfox: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?0 }
    condition:
        $a at pe.entry_point

}
rule MEW_10_by_Northfox: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40 }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_v11_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_02_MEW_11_SE_10_Anorganix: PEiD
{
    strings:
        $a = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 }
    condition:
        $a at pe.entry_point

}
rule Mew_11_SE_v12_Eng_Northfox_additional: PEiD
{
    strings:
        $a = { 06 1E 52 B8 ?? ?? 1E CD 21 86 E0 3D }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_v12_NorthfoxHCC: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_MEW_11_SE_10: PEiD
{
    strings:
        $a = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_02_MEW_11_SE_10: PEiD
{
    strings:
        $a = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 }
    condition:
        $a at pe.entry_point

}
rule MEW_5_10_Northfox_additional: PEiD
{
    strings:
        $a = { BE 48 01 ?? ?? ?? ?? ?? 95 A5 33 C0 }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_v12_Northfox: PEiD
{
    strings:
        $a = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 9D 11 40 00 8D 95 B4 11 40 00 E8 CB 2E 00 00 33 C0 F7 F0 69 8D B5 05 12 40 00 B9 5D 2E 00 00 8B FE AC }
        $b = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 9D 11 40 00 8D 95 B4 11 40 00 E8 CB 2E 00 00 33 C0 F7 F0 69 8D B5 05 12 40 00 B9 5D 2E 00 00 8B FE AC }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule MEW_5_Northfox: PEiD
{
    strings:
        $a = { BE ?? ?? ?? ?? AD 91 AD 93 53 AD 96 56 5F AC }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_01_MEW_11_SE_10_Anorganix: PEiD
{
    strings:
        $a = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_MEW_11_SE_10_Anorganix: PEiD
{
    strings:
        $a = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9 }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_v11_Northfox: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 0C ?? ?? ?? 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_v10_Northfox: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 00 00 00 02 00 00 00 0C ?0 }
        $b = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Mew_501_NorthFox_HCC_additional: PEiD
{
    strings:
        $a = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 00 ?? ?? 00 ?? ?? ?? 00 00 10 40 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E }
    condition:
        $a at pe.entry_point

}
rule MEW_10_by_Northfox_additional: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40 }
    condition:
        $a at pe.entry_point

}
rule Mew_10_exe_coder_10_Northfox_HCC: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? FF FF 6A ?? ?? ?? ?? ?? 70 }
    condition:
        $a at pe.entry_point

}
rule Mew_10_v10_Northfox: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? FF FF }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_v11_Northfox_HCC: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C }
        $b = { E9 ?? ?? ?? FF 0C ?0 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule MEW_11_SE_v12_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Mew_10_exe_coder_10_Northfox_HCC_additional: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? FF FF 6A ?? ?? ?? ?? ?? 70 }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_10_Northfox: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 00 00 00 02 00 00 00 0C 00 }
    condition:
        $a at pe.entry_point

}
rule MEW_5_10_Northfox: PEiD
{
    strings:
        $a = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 }
    condition:
        $a at pe.entry_point

}
rule Mew_10_v10_Eng_Northfox_additional: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? ?? FF }
    condition:
        $a at pe.entry_point

}
rule MEW_11_SE_v11_Northfox_HCC_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C }
    condition:
        $a at pe.entry_point

}

rule ThemidaWinLicense_V1X_Oreans_Technologies_SignByfly: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 43 4F 4D 43 54 4C 33 32 2E 64 6C 6C 00 00 00 49 6E 69 74 43 6F 6D 6D 6F 6E 43 6F 6E 74 72 6F 6C 73 00 00 00 00 00 00 }
        $b = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 43 72 65 61 74 65 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ThemidaWinLicense_V18X_V19X_Oreans_Technologies: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 05 89 48 01 61 E9 }
        $b = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Themida_1201_compressed_Oreans_Technologies_h: PEiD
{
    strings:
        $a = { B8 00 00 ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }
    condition:
        $a at pe.entry_point

}
rule Themida_18xx_Oreans_Technologies: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V10X_V17X_DLL_Oreans_Technologies_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? ?? ?? ?? 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V18X_V19X_DLL_Oreans_Technologies: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 05 89 48 01 61 E9 }
    condition:
        $a at pe.entry_point

}
rule Themida_10xx_18xx_no_compression_Oreans_Technologies_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8D 45 80 8B 5D 08 C7 85 7C FF FF FF 00 00 00 00 8B 8D 7C FF FF FF D1 C3 88 18 41 89 8D 7C FF FF FF 81 BD 7C FF FF FF 80 00 00 00 75 E3 C7 85 7C FF FF FF 00 00 00 00 8D BA ?? ?? ?? ?? 8D 75 80 8A 0E BB F4 01 00 00 B8 AB 37 54 78 D3 D0 8A 0F D3 D0 4B 75 F7 0F AF C3 47 46 8B 8D 7C FF FF FF 41 89 8D 7C FF FF FF 81 F9 80 00 00 00 75 D1 61 C9 C2 04 00 55 8B EC 83 C4 F0 8B 75 08 C7 45 FC 00 00 00 00 EB 04 FF 45 FC 46 80 3E 00 75 F7 BA 00 00 00 00 8B 75 08 8B 7D 0C EB 7F C7 45 F8 00 00 00 00 EB }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V1820_p_Oreans_Technologies: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule themida_1005_httpwwworeanscom_additional: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 }
    condition:
        $a at pe.entry_point

}
rule Themida_10xx_18xx_no_compression_Oreans_Technologies_h: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 }
        $b = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8D 45 80 8B 5D 08 C7 85 7C FF FF FF 00 00 00 00 8B 8D 7C FF FF FF D1 C3 88 18 41 89 8D 7C FF FF FF 81 BD 7C FF FF FF 80 00 00 00 75 E3 C7 85 7C FF FF FF 00 00 00 00 8D BA ?? ?? ?? ?? 8D 75 80 8A 0E BB F4 01 00 00 B8 AB 37 54 78 D3 D0 8A 0F D3 D0 4B 75 F7 0F AF C3 47 46 8B 8D 7C FF FF FF 41 89 8D 7C FF FF FF 81 F9 80 00 00 00 75 D1 61 C9 C2 04 00 55 8B EC 83 C4 F0 8B 75 08 C7 45 FC 00 00 00 00 EB 04 FF 45 FC 46 80 3E 00 75 F7 BA 00 00 00 00 8B 75 08 8B 7D 0C EB 7F C7 45 F8 00 00 00 00 EB }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ThemidaWinLicense_V2010_p_Hide_from_PE_scanners_Type2: PEiD
{
    strings:
        $a = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Themida_1201_compressed_Oreans_Technologies_h_additional: PEiD
{
    strings:
        $a = { B8 00 00 ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? 00 03 C7 B9 ?? ?? ?? 00 03 CF EB 0A B8 ?? ?? ?? ?? B9 5A ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 AF 01 00 00 02 00 00 00 91 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V1X_NoCompression_SecureEngine_Oreans_Technologies: PEiD
{
    strings:
        $a = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? ?? ?? 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V10X_V17X_DLL_Oreans_Technologies: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? ?? ?? ?? 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 ?? 89 48 01 61 E9 }
        $b = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? ?? ?? ?? 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Themida_Oreans_Technologies_2004: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 }
    condition:
        $a at pe.entry_point

}
rule Themida_1201_Oreans_Technologies: PEiD
{
    strings:
        $a = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? 35 09 89 95 ?? ?? 35 09 89 B5 ?? ?? 35 09 89 85 ?? ?? 35 09 83 BD ?? ?? 35 09 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? 35 09 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 }
        $b = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? 35 09 89 95 ?? ?? 35 09 89 B5 ?? ?? 35 09 89 85 ?? ?? 35 09 83 BD ?? ?? 35 09 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? 35 09 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 11 02 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Themida_Oreans_Technologies_2004_additional: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 }
    condition:
        $a at pe.entry_point

}
rule Themida_10xx_1800_compressed_engine_Oreans_Technologies_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }
    condition:
        $a at pe.entry_point

}
rule Themida_1920_additional: PEiD
{
    strings:
        $a = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? ?? ?? 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 14 02 00 00 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V2100_p_Oreans_Technologies_20090917: PEiD
{
    strings:
        $a = { 83 EC 04 50 53 E8 ?? ?? 00 00 CC 58 8B D8 40 2D ?? ?? ?? ?? 2D ?? ?? ?? ?? 05 ?? ?? ?? ?? 80 3B CC 75 19 C6 03 00 BB 00 10 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 50 E8 0A 00 00 00 83 C0 00 89 44 24 08 5B 58 C3 55 8B EC 60 8B 75 08 8B 4D 0C C1 E9 02 8B 45 10 8B 5D 14 EB 08 31 06 01 1E 83 C6 04 49 0B C9 75 F4 61 C9 C2 10 00 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V1820_p_Oreans_Technologies_Sign_by_fly: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Themida_v2018_c2007_Oreans_Technologies: PEiD
{
    strings:
        $a = { 83 EC 04 50 53 E8 00 00 00 00 58 8B D8 2D 00 ?? ?? 00 2D ?? ?? ?? 00 05 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule themida_1005_http58wwworeanscom: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V1X_NoCompression_SecureEngine_Oreans_Technologies_additional: PEiD
{
    strings:
        $a = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? ?? ?? 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V18X_V19Xnbsp_Oreans_Technologiesnbsp_nbsp_SignByfly: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 05 89 48 01 61 E9 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V1X_Oreans_Technologies: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 43 72 65 61 74 65 }
        $b = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 43 4F 4D 43 54 4C 33 32 2E 64 6C 6C 00 00 00 49 6E 69 74 43 6F 6D 6D 6F 6E 43 6F 6E 74 72 6F 6C 73 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Themida_1201_compressed_Oreans_Technologies: PEiD
{
    strings:
        $a = { B8 00 00 ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V18X_V19X_Other_Oreans_Technologies_20080131: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 }
    condition:
        $a at pe.entry_point

}
rule Themida_1201_Oreans_Technologies_h_additional: PEiD
{
    strings:
        $a = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? 35 09 89 95 ?? ?? 35 09 89 B5 ?? ?? 35 09 89 85 ?? ?? 35 09 83 BD ?? ?? 35 09 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? 35 09 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 11 02 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Themida_1920: PEiD
{
    strings:
        $a = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? ?? ?? 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 14 02 00 00 }
        $b = { BE ?? ?? BF ?? ?? B9 ?? ?? 56 FC F3 A5 5F E9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Themida_18xx_19xx_Oreans_Technologies: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V1X_V2X_Oreans_Technologies: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 43 4F 4D 43 54 4C 33 32 2E 64 6C 6C 00 00 00 49 6E 69 74 43 6F 6D 6D 6F 6E 43 6F 6E 74 72 6F 6C 73 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Themida_10xx_18xx_no_compression_Oreans_Technologies: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 }
        $b = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8D 45 80 8B 5D 08 C7 85 7C FF FF FF 00 00 00 00 8B 8D 7C FF FF FF D1 C3 88 18 41 89 8D 7C FF FF FF 81 BD 7C FF FF FF 80 00 00 00 75 E3 C7 85 7C FF FF FF 00 00 00 00 8D BA ?? ?? ?? ?? 8D 75 80 8A 0E BB F4 01 00 00 B8 AB 37 54 78 D3 D0 8A 0F D3 D0 4B 75 F7 0F AF C3 47 46 8B 8D 7C FF FF FF 41 89 8D 7C FF FF FF 81 F9 80 00 00 00 75 D1 61 C9 C2 04 00 55 8B EC 83 C4 F0 8B 75 08 C7 45 FC 00 00 00 00 EB 04 FF 45 FC 46 80 3E 00 75 F7 BA 00 00 00 00 8B 75 08 8B 7D 0C EB 7F C7 45 F8 00 00 00 00 EB }
        $c = { 55 8B EC 83 C4 D8 60 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule Themida_10xx_1800_compressed_engine_Oreans_Technologies: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }
    condition:
        $a at pe.entry_point

}
rule themida_1005_httpwwworeanscom: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V1000_V1800_Oreans_Technologies: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V1802_p_Oreans_Technologies: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Themida_18xx_Oreans_Technologies_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 }
    condition:
        $a at pe.entry_point

}
rule Themida_10xx_18xx_no_compression_Oreans_Technologies_h_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8D 45 80 8B 5D 08 C7 85 7C FF FF FF 00 00 00 00 8B 8D 7C FF FF FF D1 C3 88 18 41 89 8D 7C FF FF FF 81 BD 7C FF FF FF 80 00 00 00 75 E3 C7 85 7C FF FF FF 00 00 00 00 8D BA ?? ?? ?? ?? 8D 75 80 8A 0E BB F4 01 00 00 B8 AB 37 54 78 D3 D0 8A 0F D3 D0 4B 75 F7 0F AF C3 47 46 8B 8D 7C FF FF FF 41 89 8D 7C FF FF FF 81 F9 80 00 00 00 75 D1 61 C9 C2 04 00 55 8B EC 83 C4 F0 8B 75 08 C7 45 FC 00 00 00 00 EB 04 FF 45 FC 46 80 3E 00 75 F7 BA 00 00 00 00 8B 75 08 8B 7D 0C EB 7F C7 45 F8 00 00 00 00 EB }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V18X_V19X_Other_Oreans_Technologies_SignByfly_20080131: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V1802_p_Oreans_Technologies_additional: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule ThemidaWinLicense_V18X_V2X_Oreans_Technologies_20080131: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 }
    condition:
        $a at pe.entry_point

}
rule Themida_v2065_or_newer_c2009_Oreans_Technologies: PEiD
{
    strings:
        $a = { 52 BA 64 00 00 00 EB 1B B9 00 10 00 00 EB 05 03 C1 03 C3 49 0B C9 75 F7 52 54 54 FF 15 }
    condition:
        $a at pe.entry_point

}
rule Themida_v2010_v2065_or_newer: PEiD
{
    strings:
        $a = { 83 EC 04 50 53 E8 ?? 00 00 00 CC 58 8B D8 40 2D 00 ?? ?? 00 2D ?? ?? ?? 00 05 ?? ?? ?? 00 80 3B CC 75 19 C6 03 00 BB 00 10 00 00 68 }
    condition:
        $a at pe.entry_point

}
rule Themida_1201_Oreans_Technologies_h: PEiD
{
    strings:
        $a = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? 35 09 89 95 ?? ?? 35 09 89 B5 ?? ?? 35 09 89 85 ?? ?? 35 09 83 BD ?? ?? 35 09 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? 35 09 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 }
        $b = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? 35 09 89 95 ?? ?? 35 09 89 B5 ?? ?? 35 09 89 85 ?? ?? 35 09 83 BD ?? ?? 35 09 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? 35 09 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 11 02 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule ThemidaWinLicense_V1000_V1800_Oreans_Technologies_Sign_by_fly: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}

rule ExeStealth_WebToolMaster: PEiD
{
    strings:
        $a = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F }
    condition:
        $a at pe.entry_point

}
rule EXEStealth_v275a_WebtoolMaster_h_additional: PEiD
{
    strings:
        $a = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 90 60 90 E8 00 00 00 00 5D 81 ED F7 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 96 0C 00 00 90 8D BD 74 28 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 C5 }
    condition:
        $a at pe.entry_point

}
rule EXEStealth_275_WebtoolMaster_additional: PEiD
{
    strings:
        $a = { 33 C9 B4 4E CD 21 73 02 FF ?? BA ?? 00 B8 ?? 3D CD 21 }
    condition:
        $a at pe.entry_point

}
rule EXEStealth_276_Unregistered_WebtoolMaster_additional: PEiD
{
    strings:
        $a = { EB ?? 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 53 68 61 72 65 77 61 72 65 20 }
    condition:
        $a at pe.entry_point

}
rule EXEStealth_276_Unregistered_WebtoolMaster: PEiD
{
    strings:
        $a = { EB ?? 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 53 68 61 72 65 77 61 72 65 20 }
    condition:
        $a at pe.entry_point

}
rule EXEStealth_275_WebtoolMaster: PEiD
{
    strings:
        $a = { 90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule EXEStealth_v275a_WebtoolMaster: PEiD
{
    strings:
        $a = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 90 60 90 E8 00 00 00 00 5D 81 ED F7 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 96 0C 00 00 90 8D BD 74 28 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 C5 }
    condition:
        $a at pe.entry_point

}
rule ExeStealth_WebToolMaster_additional: PEiD
{
    strings:
        $a = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F }
    condition:
        $a at pe.entry_point

}
rule EXEStealth_v275a_WebtoolMaster_h: PEiD
{
    strings:
        $a = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 }
    condition:
        $a at pe.entry_point

}

rule MPRESS_V097_V099_MATCODE_Softwarenbsp_nbsp_SignByfly_20080416: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 05 49 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 3B FE 73 28 AC 0A C0 74 23 8A C8 24 3F C1 E0 10 66 AD 80 E1 40 74 0F 8B D6 8B CF 03 F0 E8 60 00 00 00 03 F8 EB D8 8B C8 F3 A4 EB D2 5E 5A 83 EA 05 2B C9 3B CA 73 26 8B D9 AC 41 24 FE 3C E8 75 F2 43 83 C1 04 AD 0B C0 78 06 3B C2 73 E5 EB 06 03 C3 78 DF 03 C2 2B C3 89 46 FC EB D6 E8 00 00 00 00 5F 81 C7 69 FF FF FF B0 E9 AA B8 45 01 00 00 AB E8 00 00 00 00 58 05 A3 00 00 00 E9 93 00 00 00 53 56 57 8B F9 8B F2 8B DA 03 D8 51 55 33 C0 8B EB 8B DE 2B D2 2B C9 EB 4F 3B DD 73 6C 2B C9 66 8B 03 8D 5B 02 8A CC 80 E4 0F 0B C0 75 02 B4 10 C0 E9 04 80 C1 03 80 F9 12 72 19 8A 0B 66 83 C1 12 43 66 81 F9 11 01 72 0B 66 8B 0B 81 C1 11 01 00 00 43 43 8B F7 2B F0 F3 A4 12 D2 74 0A 72 B9 8A 03 43 88 07 47 EB F2 3B DD 73 1D 0A 13 F9 74 03 43 EB E6 8B 43 01 89 07 8B 43 05 89 47 04 8D 5B 09 8D 7F 08 33 C0 EB DF 5D 8B C7 59 2B C1 5F 5E 5B C3 E9 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V107_V125_MATCODE_Softwarenbsp_nbsp_SignByfly_20080730: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 05 9E 02 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 8B D6 8B CF E8 56 00 00 00 5E 5A 83 EA 05 2B C9 3B CA 73 26 8B D9 AC 41 24 FE 3C E8 75 F2 43 83 C1 04 AD 0B C0 78 06 3B C2 73 E5 EB 06 03 C3 78 DF 03 C2 2B C3 89 46 FC EB D6 E8 00 00 00 00 5F 81 C7 8D FF FF FF B0 E9 AA B8 9A 02 00 00 AB E8 00 00 00 00 58 05 1C 02 00 00 E9 0C 02 00 00 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V107_V125_MATCODE_Software_20080730: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 05 9E 02 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 8B D6 8B CF E8 56 00 00 00 5E 5A 83 EA 05 2B C9 3B CA 73 26 8B D9 AC 41 24 FE 3C E8 75 F2 43 83 C1 04 AD 0B C0 78 06 3B C2 73 E5 EB 06 03 C3 78 DF 03 C2 2B C3 89 46 FC EB D6 E8 00 00 00 00 5F 81 C7 8D FF FF FF B0 E9 AA B8 9A 02 00 00 AB E8 00 00 00 00 58 05 1C 02 00 00 E9 0C 02 00 00 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V200_V20X_MATCODE_Software_20090423: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 88 04 31 75 F6 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V085_V092_MATCODE_Softwarenbsp_nbsp_SignByfly_20080414: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 05 48 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 3B FE 73 28 AC 0A C0 74 23 8A C8 24 3F C1 E0 10 66 AD 80 E1 40 74 0F 8B D6 8B CF 03 F0 E8 5F 00 00 00 03 F8 EB D8 8B C8 F3 A4 EB D2 5E 5A 83 EA 05 2B C9 3B CA 73 25 8B D9 AC 41 24 FE 3C E8 75 F2 83 C1 04 AD 0B C0 78 06 3B C2 73 E6 EB 06 03 C3 78 E0 03 C2 2B C3 89 46 FC EB D7 E8 00 00 00 00 5F 81 C7 6A FF FF FF B0 E9 AA B8 44 01 00 00 AB E8 00 00 00 00 58 05 A3 00 00 00 E9 93 00 00 00 53 56 57 8B F9 8B F2 8B DA 03 D8 51 55 33 C0 8B EB 8B DE 2B D2 2B C9 EB 4F 3B DD 73 6C 2B C9 66 8B 03 8D 5B 02 8A CC 80 E4 0F 0B C0 75 02 B4 10 C0 E9 04 80 C1 03 80 F9 12 72 19 8A 0B 66 83 C1 12 43 66 81 F9 11 01 72 0B 66 8B 0B 81 C1 11 01 00 00 43 43 8B F7 2B F0 F3 A4 12 D2 74 0A 72 B9 8A 03 43 88 07 47 EB F2 3B DD 73 1D 0A 13 F9 74 03 43 EB E6 8B 43 01 89 07 8B 43 05 89 47 04 8D 5B 09 8D 7F 08 33 C0 EB DF 5D 8B C7 59 2B C1 5F 5E 5B C3 E9 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V071a_V075b_MATCODE_Softwarenbsp_nbsp_SignByfly_20080310: PEiD
{
    strings:
        $a = { 57 56 53 51 52 55 E8 10 00 00 00 E8 7A 00 00 00 5D 5A 59 5B 5E 5F E9 84 01 00 00 E8 00 00 00 00 58 05 84 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 AD 2B C8 03 F1 8B C8 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 AC 0A C0 74 37 8A C8 24 3F 80 E1 C0 C1 E0 10 66 AD 80 F9 C0 74 1E F6 C1 40 75 0A 8B C8 2B C0 F3 AA 75 FC EB D9 8B D6 8B CF 03 F0 E8 8F 00 00 00 03 F8 EB CA 8B C8 F3 A4 75 FC EB C2 C3 E8 00 00 00 00 5F 81 C7 71 FF FF FF B0 E9 AA B8 9A 01 00 00 AB 2B FF E8 00 00 00 00 58 05 FE 00 00 00 8B 78 08 8B D7 8B 78 04 0B FF 74 53 8B 30 03 F0 2B F2 8B EE 8B C2 8B 45 3C 03 C5 8B 48 34 2B CD 74 3D E8 00 00 00 00 58 05 DD 00 00 00 8B 10 03 F2 03 FE 2B C0 AD 3B F7 73 25 8B D8 AD 3B F7 73 1E 8B D0 83 EA 08 03 D6 66 AD 0A E4 74 0B 25 FF 0F 00 00 03 C3 03 C5 29 08 3B F2 73 D8 EB E9 C3 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V097_V099_MATCODE_Software_20080416: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 05 49 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 3B FE 73 28 AC 0A C0 74 23 8A C8 24 3F C1 E0 10 66 AD 80 E1 40 74 0F 8B D6 8B CF 03 F0 E8 60 00 00 00 03 F8 EB D8 8B C8 F3 A4 EB D2 5E 5A 83 EA 05 2B C9 3B CA 73 26 8B D9 AC 41 24 FE 3C E8 75 F2 43 83 C1 04 AD 0B C0 78 06 3B C2 73 E5 EB 06 03 C3 78 DF 03 C2 2B C3 89 46 FC EB D6 E8 00 00 00 00 5F 81 C7 69 FF FF FF B0 E9 AA B8 45 01 00 00 AB E8 00 00 00 00 58 05 A3 00 00 00 E9 93 00 00 00 53 56 57 8B F9 8B F2 8B DA 03 D8 51 55 33 C0 8B EB 8B DE 2B D2 2B C9 EB 4F 3B DD 73 6C 2B C9 66 8B 03 8D 5B 02 8A CC 80 E4 0F 0B C0 75 02 B4 10 C0 E9 04 80 C1 03 80 F9 12 72 19 8A 0B 66 83 C1 12 43 66 81 F9 11 01 72 0B 66 8B 0B 81 C1 11 01 00 00 43 43 8B F7 2B F0 F3 A4 12 D2 74 0A 72 B9 8A 03 43 88 07 47 EB F2 3B DD 73 1D 0A 13 F9 74 03 43 EB E6 8B 43 01 89 07 8B 43 05 89 47 04 8D 5B 09 8D 7F 08 33 C0 EB DF 5D 8B C7 59 2B C1 5F 5E 5B C3 E9 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V085_V092_MATCODE_Software_20080414: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 05 48 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 3B FE 73 28 AC 0A C0 74 23 8A C8 24 3F C1 E0 10 66 AD 80 E1 40 74 0F 8B D6 8B CF 03 F0 E8 5F 00 00 00 03 F8 EB D8 8B C8 F3 A4 EB D2 5E 5A 83 EA 05 2B C9 3B CA 73 25 8B D9 AC 41 24 FE 3C E8 75 F2 83 C1 04 AD 0B C0 78 06 3B C2 73 E6 EB 06 03 C3 78 E0 03 C2 2B C3 89 46 FC EB D7 E8 00 00 00 00 5F 81 C7 6A FF FF FF B0 E9 AA B8 44 01 00 00 AB E8 00 00 00 00 58 05 A3 00 00 00 E9 93 00 00 00 53 56 57 8B F9 8B F2 8B DA 03 D8 51 55 33 C0 8B EB 8B DE 2B D2 2B C9 EB 4F 3B DD 73 6C 2B C9 66 8B 03 8D 5B 02 8A CC 80 E4 0F 0B C0 75 02 B4 10 C0 E9 04 80 C1 03 80 F9 12 72 19 8A 0B 66 83 C1 12 43 66 81 F9 11 01 72 0B 66 8B 0B 81 C1 11 01 00 00 43 43 8B F7 2B F0 F3 A4 12 D2 74 0A 72 B9 8A 03 43 88 07 47 EB F2 3B DD 73 1D 0A 13 F9 74 03 43 EB E6 8B 43 01 89 07 8B 43 05 89 47 04 8D 5B 09 8D 7F 08 33 C0 EB DF 5D 8B C7 59 2B C1 5F 5E 5B C3 E9 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V077b_MATCODE_Softwarenbsp_nbsp_SignByfly_20080313: PEiD
{
    strings:
        $a = { 60 E8 0B 00 00 00 E8 77 00 00 00 61 E9 75 01 00 00 E8 00 00 00 00 58 05 75 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 AD 2B C8 03 F1 8B C8 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 3B FE 73 3A AC 0A C0 74 35 8A C8 24 3F 80 E1 C0 C1 E0 10 66 AD 80 F9 C0 74 1C F6 C1 40 75 08 8B C8 2B C0 F3 AA EB D7 8B D6 8B CF 03 F0 E8 7E 00 00 00 03 F8 EB C8 8B C8 F3 A4 75 FC EB C0 C3 E8 00 00 00 00 5F 81 C7 79 FF FF FF B0 E9 AA B8 81 01 00 00 AB 2B FF E8 00 00 00 00 58 05 ED 00 00 00 8B 78 08 8B D7 8B 78 04 0B FF 74 42 8B 30 03 F0 2B F2 8B EE 8B 48 10 2B CD 74 33 8B 50 0C 03 F2 03 FE 2B C0 AD 3B F7 73 25 8B D8 AD 3B F7 73 1E 8B D0 83 EA 08 03 D6 66 AD 0A E4 74 0B 25 FF 0F 00 00 03 C3 03 C5 29 08 3B F2 73 D8 EB E9 C3 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V101_MATCODE_Software_20080730: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 8B D6 8B CF E8 56 00 00 00 5E 5A 83 EA 05 2B C9 3B CA 73 26 8B D9 AC 41 24 FE 3C E8 75 F2 43 83 C1 04 AD 0B C0 78 06 3B C2 73 E5 EB 06 03 C3 78 DF 03 C2 2B C3 89 46 FC EB D6 E8 00 00 00 00 5F 81 C7 8D FF FF FF B0 E9 AA B8 B2 02 00 00 AB E8 00 00 00 00 58 05 34 02 00 00 E9 24 02 00 00 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V071a_V075b_MATCODE_Software_20080310: PEiD
{
    strings:
        $a = { 57 56 53 51 52 55 E8 10 00 00 00 E8 7A 00 00 00 5D 5A 59 5B 5E 5F E9 84 01 00 00 E8 00 00 00 00 58 05 84 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 AD 2B C8 03 F1 8B C8 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 AC 0A C0 74 37 8A C8 24 3F 80 E1 C0 C1 E0 10 66 AD 80 F9 C0 74 1E F6 C1 40 75 0A 8B C8 2B C0 F3 AA 75 FC EB D9 8B D6 8B CF 03 F0 E8 8F 00 00 00 03 F8 EB CA 8B C8 F3 A4 75 FC EB C2 C3 E8 00 00 00 00 5F 81 C7 71 FF FF FF B0 E9 AA B8 9A 01 00 00 AB 2B FF E8 00 00 00 00 58 05 FE 00 00 00 8B 78 08 8B D7 8B 78 04 0B FF 74 53 8B 30 03 F0 2B F2 8B EE 8B C2 8B 45 3C 03 C5 8B 48 34 2B CD 74 3D E8 00 00 00 00 58 05 DD 00 00 00 8B 10 03 F2 03 FE 2B C0 AD 3B F7 73 25 8B D8 AD 3B F7 73 1E 8B D0 83 EA 08 03 D6 66 AD 0A E4 74 0B 25 FF 0F 00 00 03 C3 03 C5 29 08 3B F2 73 D8 EB E9 C3 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V077b_MATCODE_Software_20080313: PEiD
{
    strings:
        $a = { 60 E8 0B 00 00 00 E8 77 00 00 00 61 E9 75 01 00 00 E8 00 00 00 00 58 05 75 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 AD 2B C8 03 F1 8B C8 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 3B FE 73 3A AC 0A C0 74 35 8A C8 24 3F 80 E1 C0 C1 E0 10 66 AD 80 F9 C0 74 1C F6 C1 40 75 08 8B C8 2B C0 F3 AA EB D7 8B D6 8B CF 03 F0 E8 7E 00 00 00 03 F8 EB C8 8B C8 F3 A4 75 FC EB C0 C3 E8 00 00 00 00 5F 81 C7 79 FF FF FF B0 E9 AA B8 81 01 00 00 AB 2B FF E8 00 00 00 00 58 05 ED 00 00 00 8B 78 08 8B D7 8B 78 04 0B FF 74 42 8B 30 03 F0 2B F2 8B EE 8B 48 10 2B CD 74 33 8B 50 0C 03 F2 03 FE 2B C0 AD 3B F7 73 25 8B D8 AD 3B F7 73 1E 8B D0 83 EA 08 03 D6 66 AD 0A E4 74 0B 25 FF 0F 00 00 03 C3 03 C5 29 08 3B F2 73 D8 EB E9 C3 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V107_V12X_MATCODE_Software_20080730: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 05 9E 02 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 8B D6 8B CF E8 56 00 00 00 5E 5A 83 EA 05 2B C9 3B CA 73 26 8B D9 AC 41 24 FE 3C E8 75 F2 43 83 C1 04 AD 0B C0 78 06 3B C2 73 E5 EB 06 03 C3 78 DF 03 C2 2B C3 89 46 FC EB D6 E8 00 00 00 00 5F 81 C7 8D FF FF FF B0 E9 AA B8 9A 02 00 00 AB E8 00 00 00 00 58 05 1C 02 00 00 E9 0C 02 00 00 }
    condition:
        $a at pe.entry_point

}
rule MPRESS_V101_MATCODE_Softwarenbsp_nbsp_SignByfly_20080730: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 8B D6 8B CF E8 56 00 00 00 5E 5A 83 EA 05 2B C9 3B CA 73 26 8B D9 AC 41 24 FE 3C E8 75 F2 43 83 C1 04 AD 0B C0 78 06 3B C2 73 E5 EB 06 03 C3 78 DF 03 C2 2B C3 89 46 FC EB D6 E8 00 00 00 00 5F 81 C7 8D FF FF FF B0 E9 AA B8 B2 02 00 00 AB E8 00 00 00 00 58 05 34 02 00 00 E9 24 02 00 00 }
    condition:
        $a at pe.entry_point

}

rule UPX_v30_EXE_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? 00 57 83 C3 04 53 68 ?? ?? ?? 00 56 }
    condition:
        $a at pe.entry_point

}
rule UPX_v070_Hint_WIN_EP: PEiD
{
    strings:
        $a = { 8C CB B9 ?? ?? BE ?? ?? 89 F7 1E A9 ?? ?? 8D ?? ?? ?? 8E D8 05 ?? ?? 8E C0 FD F3 A5 FC 2E ?? ?? ?? ?? 73 }
    condition:
        $a at pe.entry_point

}
rule UPX_020_EXE: PEiD
{
    strings:
        $a = { 8C CB B9 00 00 BE 00 00 89 F7 1E A9 B5 80 8D 87 05 00 8E D8 05 00 00 8E C0 FD F3 A5 FC 2E 80 6C 13 10 73 E8 AF AD 0E 0E 0E 06 1F 07 16 68 00 00 BD FF FF F7 E1 93 CB 55 50 58 21 03 03 02 07 }
    condition:
        $a at pe.entry_point

}
rule UPX_v0896_v102_v105_v122_Delphi_stub_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B }
    condition:
        $a at pe.entry_point

}
rule UPX_Protector_v10x_2: PEiD
{
    strings:
        $a = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }
    condition:
        $a at pe.entry_point

}
rule UPX_302: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C }
    condition:
        $a at pe.entry_point

}
rule UPX_Scrambler_RC_v1x: PEiD
{
    strings:
        $a = { 90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
        $b = { 66 C7 05 ?? ?? ?? ?? 75 07 E9 ?? FE FF FF 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_v0896_v102_v105_v122_Delphi_stub_Laszlo_Markus: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B }
    condition:
        $a at pe.entry_point

}
rule UPX_Modified_Stub_b_Farb_rausch_Consumer_Consulting: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC }
    condition:
        $a at pe.entry_point

}
rule Simple_UPX_Cryptor_v3042005_One_layer_encryption_MANtiCORE: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
    condition:
        $a at pe.entry_point

}
rule UPX_Modified_Stub_c_Farb_rausch_Consumer_Consulting: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48 }
    condition:
        $a at pe.entry_point

}
rule UPX_200_30X_Markus_Oberhumer_amp_Laszlo_Molnar_amp_John_Reiser: PEiD
{
    strings:
        $a = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF ?? ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 57 48 F2 AE 55 FF ?? ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB E1 FF ?? ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? ?? ?? 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }
        $b = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_070_PE_DLL: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 99 01 00 00 60 E8 00 00 00 00 58 83 E8 48 50 8D B8 00 00 00 FF 57 66 81 87 00 00 00 00 00 00 8D B0 FC 01 00 00 83 CD FF 31 DB EB 0C 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_Alternative_stub_additional: PEiD
{
    strings:
        $a = { B9 ?? ?? BE ?? ?? BF C0 FF FD }
    condition:
        $a at pe.entry_point

}
rule UPX_123_Markus_Laszlo: PEiD
{
    strings:
        $a = { 31 2E 32 33 00 55 50 58 }
    condition:
        $a at pe.entry_point

}
rule UPX_071_072_PE: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE FA 00 00 FF 57 66 81 87 00 00 00 00 00 00 81 C6 B3 01 00 00 EB 0A 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 }
    condition:
        $a at pe.entry_point

}
rule UPX_Modified_Stub_b_Farb_rausch_Consumer_Consulting_: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 31 C0 31 DB 31 C9 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 89 D8 E2 D9 8D BE ?? ?? ?? ?? 8B 07 09 C0 74 45 8B 5F 04 8D 84 30 ?? ?? ?? ?? 01 F3 50 83 C7 08 FF 96 ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 ?? ?? ?? ?? 61 E9 }
    condition:
        $a at pe.entry_point

}
rule UPX_v062_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 EC 01 ?? ?? 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 07 }
    condition:
        $a at pe.entry_point

}
rule PackerUPX_CompresorGratuito_wwwupxsourceforgenet: PEiD
{
    strings:
        $a = { 60 BE ?? ?0 ?? 00 8D BE ?? ?? F? FF }
    condition:
        $a at pe.entry_point

}
rule UPX_050_070: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D }
    condition:
        $a at pe.entry_point

}
rule UPX_071_072_PE_DLL: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE EF 00 00 FF 57 66 81 87 00 00 00 00 00 00 81 C6 B1 01 00 00 EB 07 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE }
    condition:
        $a at pe.entry_point

}
rule UPX_v0761_dos_exe_additional: PEiD
{
    strings:
        $a = { B9 ?? ?? BE ?? ?? 89 F7 1E A9 ?? ?? 8C C8 05 ?? ?? 8E D8 05 ?? ?? 8E C0 FD F3 A5 FC }
    condition:
        $a at pe.entry_point

}
rule Simple_UPX_Cryptor_v3042005_One_layer_encryption_MANtiCORE_: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
    condition:
        $a at pe.entry_point

}
rule UPX_V194_Markus_Oberhumer_Laszlo_Molnar_John_Reiser: PEiD
{
    strings:
        $a = { FF D5 80 A7 ?? ?? ?? ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        $a at pe.entry_point

}
rule Simple_UPX_Cryptor_v3042005_multi_layer_encryption_MANtiCORE_: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? ?? B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? ?? C3 }
    condition:
        $a at pe.entry_point

}
rule UPX_com: PEiD
{
    strings:
        $a = { B9 ?? ?? BE ?? ?? BF C0 FF FD }
    condition:
        $a at pe.entry_point

}
rule UPX_Alternative_stub_Laszlo_Markus: PEiD
{
    strings:
        $a = { EB 02 EB EA EB FC 8A 06 }
    condition:
        $a at pe.entry_point

}
rule UPX_v080_v084_additional: PEiD
{
    strings:
        $a = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }
    condition:
        $a at pe.entry_point

}
rule UPX_v071_DLL_additional: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 83 }
    condition:
        $a at pe.entry_point

}
rule UPX_v072_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 83 ?? ?? 31 DB 5E 8D ?? ?? ?? ?? ?? 57 66 ?? ?? ?? ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? EB }
    condition:
        $a at pe.entry_point

}
rule UPXLock_v11_CyberDoom_Bob_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? 00 60 }
    condition:
        $a at pe.entry_point

}
rule UPX_v0896_v102_v105_v122_DLL_additional: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
    condition:
        $a at pe.entry_point

}
rule UPX_p_ECLiPSE_layer: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01 }
    condition:
        $a at pe.entry_point

}
rule UPXHiT_001_sibaway7yahoocom: PEiD
{
    strings:
        $a = { E2 FA 94 FF E0 61 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule MSLRH_v032a_fake_UPX_0896_102_105_124_emadicius_h: PEiD
{
    strings:
        $a = { 60 BE 00 90 8B 00 8D BE 00 80 B4 FF 57 83 CD FF EB 3A 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 58 61 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
    condition:
        $a at pe.entry_point

}
rule UPX_v20_Markus_Laszlo_Reiser_h_additional: PEiD
{
    strings:
        $a = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? 00 00 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        $a at pe.entry_point

}
rule Simple_UPX_Cryptor_V3042005_MANtiCORE_additional: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? ?? ?? ?? ?? E2 FA 61 68 ?? ?? ?? ?? C3 }
    condition:
        $a at pe.entry_point

}
rule Simple_UPX_Cryptor_v3042005_multi_layer_encryption_additional: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? ?? B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? ?? C3 }
    condition:
        $a at pe.entry_point

}
rule Upx_Lock_v10_CyberDoom_Team_X: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }
    condition:
        $a at pe.entry_point

}
rule UPX_v081_v084_Modified: PEiD
{
    strings:
        $a = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }
        $b = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_V194_Markus_Oberhumer_Laszlo_Molnar_John_Reiser_additional: PEiD
{
    strings:
        $a = { FF D5 80 A7 ?? ?? ?? ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        $a at pe.entry_point

}
rule UPX_p_ECLiPSE_layer_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01 }
    condition:
        $a at pe.entry_point

}
rule UPX_120_Markus_Laszlo: PEiD
{
    strings:
        $a = { 31 2E 32 30 00 55 50 58 }
    condition:
        $a at pe.entry_point

}
rule UPX_124_Markus_Laszlo: PEiD
{
    strings:
        $a = { 31 2E 32 34 00 55 50 58 }
    condition:
        $a at pe.entry_point

}
rule UPX_Modifier_v01x: PEiD
{
    strings:
        $a = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
    condition:
        $a at pe.entry_point

}
rule UPX_v0761_pe_exe: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 57 83 ?? ?? 31 DB EB }
    condition:
        $a at pe.entry_point

}
rule UPX_Modified_stub_additional: PEiD
{
    strings:
        $a = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
    condition:
        $a at pe.entry_point

}
rule Simple_UPX_Cryptor_v3042005_multi_layer_encryption: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }
        $b = { 60 B8 ?? ?? ?? 00 B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPXHiT_v001_DJ_Siba: PEiD
{
    strings:
        $a = { 94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }
    condition:
        $a at pe.entry_point

}
rule UPX_v060_v061: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 FF 57 66 81 87 8D B0 F0 01 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 }
        $b = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 E8 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_293_LZMA: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }
    condition:
        $a at pe.entry_point

}
rule UPX_wwwupxsourceforgenet_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? 00 8D BE ?? ?? ?? FF }
    condition:
        $a at pe.entry_point

}
rule UPX_051_PE: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 D8 01 00 00 83 CD FF 31 DB 90 90 90 90 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB 90 90 90 B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF 75 }
    condition:
        $a at pe.entry_point

}
rule UPX_v062_DLL_additional: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 58 }
    condition:
        $a at pe.entry_point

}
rule UPXFreak_v01_Borland_Delphi_HMX0101_additional: PEiD
{
    strings:
        $a = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_200_30X_Markus_Oberhumer_amp_Laszlo_Molnar_amp_John_Reiser_additional: PEiD
{
    strings:
        $a = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF }
    condition:
        $a at pe.entry_point

}
rule UPX_v30_DLL_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser_additional: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 C7 0B 00 00 60 BE 00 ?? ?? ?? 8D BE 00 ?? ?? FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_02_UPX_06_Anorganix: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_v0896_v102_v105_v122: PEiD
{
    strings:
        $a = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 }
        $b = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_Modified_Stub_b_Farb_rausch_Consumer_Consulting_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 57 83 ?? ?? 31 DB EB }
    condition:
        $a at pe.entry_point

}
rule UPX_v080_v084: PEiD
{
    strings:
        $a = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
        $b = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF 75 09 8B 1E 83 EE FC }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule SkD_Undetectabler_Pro_20_No_UPX_Method_SkD: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 B8 FC 26 00 10 E8 EC F3 FF FF 6A 0F E8 15 F5 FF FF E8 64 FD FF FF E8 BB ED FF FF 8D 40 }
    condition:
        $a at pe.entry_point

}
rule UPX_v103_v104_Modified_additional: PEiD
{
    strings:
        $a = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }
    condition:
        $a at pe.entry_point

}
rule UPX_v20_Markus_Laszlo_Reiser: PEiD
{
    strings:
        $a = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? 00 00 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 }
        $b = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? 00 00 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_V194_Markus_Oberhumer_amp_Laszlo_Molnar_amp_John_Reiser: PEiD
{
    strings:
        $a = { FF D5 80 A7 ?? ?? ?? ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        $a at pe.entry_point

}
rule UPX_0896_102_PE: PEiD
{
    strings:
        $a = { 60 BE 00 00 00 00 8D BE 00 00 00 FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 }
    condition:
        $a at pe.entry_point

}
rule Unknown_UPX_modifyer: PEiD
{
    strings:
        $a = { E8 02 00 00 00 CD 03 5A 81 C2 ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 89 D1 81 C1 3C 05 00 00 52 81 2A 33 53 45 12 83 C2 04 39 CA 7E F3 89 CA 8B 42 04 8D 18 29 02 BB 78 56 00 00 83 EA 04 3B 14 24 7D EC C3 }
    condition:
        $a at pe.entry_point

}
rule UPX_030_EXE: PEiD
{
    strings:
        $a = { 8C CB B9 00 00 BE 00 00 89 F7 1E A9 B5 80 8D 87 05 00 8E D8 05 00 00 8E C0 FD F3 A5 FC 2E 80 6C 13 10 73 E8 AF AD 0E 0E 0E 06 1F 07 16 68 00 00 BD FF FF F7 E1 93 CB 55 50 58 21 04 03 02 07 }
    condition:
        $a at pe.entry_point

}
rule UPXHiT_v001: PEiD
{
    strings:
        $a = { 94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }
    condition:
        $a at pe.entry_point

}
rule Password_Protector_for_the_UPX_030_g0d_additional: PEiD
{
    strings:
        $a = { C8 50 01 00 60 E8 EC 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 44 69 61 6C 6F 67 42 6F 78 49 6E 64 69 72 65 63 74 50 61 72 61 6D 41 00 53 65 6E 64 4D 65 73 73 61 67 65 41 00 45 6E 64 44 69 61 6C 6F 67 00 00 00 55 8B EC 57 BF 00 00 00 00 33 C0 81 6D 0C 10 01 00 00 75 03 40 EB 13 83 7D 0C 01 75 0D 66 83 7D 10 0B 75 0B FF 75 14 8F 47 E4 5F 5D C2 10 00 66 83 7D 10 02 77 F4 74 0E 8D 4F A0 51 6A 40 6A 0D FF 77 E4 FF 57 E8 50 FF 75 08 FF 57 EC EB DB 84 08 C8 90 00 00 00 00 01 00 64 00 64 00 64 00 14 00 00 00 00 00 45 00 6E 00 74 00 65 00 72 00 20 00 50 00 61 00 73 00 73 00 77 00 6F 00 72 00 64 00 00 00 A0 00 00 50 00 00 02 00 05 00 05 00 5A 00 0A 00 0B 00 FF FF 81 00 00 00 00 00 5E FC 8D BE AA FE FF FF 8D 86 }
    condition:
        $a at pe.entry_point

}
rule UPX_0896_PE_DLL: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 00 00 00 00 60 BE 1A 00 00 00 8D BE E6 00 00 FF 57 83 CD FF EB 0D 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC }
    condition:
        $a at pe.entry_point

}
rule UPX_Protector_v10x_additional: PEiD
{
    strings:
        $a = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_02_UPX_06: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_072_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E }
    condition:
        $a at pe.entry_point

}
rule UPX_290_LZMA_Delphi_stub_Markus_Oberhumer_Laszlo_Molnar_John_Reiser: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 }
    condition:
        $a at pe.entry_point

}
rule UPX_200_Markus_Laszlo: PEiD
{
    strings:
        $a = { 32 2E 30 30 00 55 50 58 }
    condition:
        $a at pe.entry_point

}
rule UPX_v103_v104_Laszlo_Markus: PEiD
{
    strings:
        $a = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }
    condition:
        $a at pe.entry_point

}
rule UPX_v30_DLL_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 C7 0B 00 00 60 BE 00 ?? ?? ?? 8D BE 00 ?? ?? FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_SCRAMBLER_306_OnToL_additional: PEiD
{
    strings:
        $a = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 BE ?? ?? ?? ?? 83 EC 04 89 34 24 B9 80 00 00 00 81 36 ?? ?? ?? ?? 50 B8 04 00 00 00 50 03 34 24 58 58 83 E9 03 E2 E9 EB D6 }
    condition:
        $a at pe.entry_point

}
rule UPXHiT_001_DJ_Siba: PEiD
{
    strings:
        $a = { E2 FA 94 FF E0 61 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_com_additional: PEiD
{
    strings:
        $a = { B9 ?? ?? BE ?? ?? BF C0 FF FD }
    condition:
        $a at pe.entry_point

}
rule UPX_Shit_v01_500mhz: PEiD
{
    strings:
        $a = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 01 ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }
        $b = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 01 ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 20 5B 35 30 30 6D 68 7A 5D }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_v070_Laszlo_Markus: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 EC 01 ?? ?? 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 07 }
    condition:
        $a at pe.entry_point

}
rule UPX_200_30X_Markus_Oberhumer_Laszlo_Molnar_John_Reiser: PEiD
{
    strings:
        $a = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF ?? ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 57 48 F2 AE 55 FF ?? ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB E1 FF ?? ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? ?? ?? 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }
        $b = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_093_UnHack32_11: PEiD
{
    strings:
        $a = { 60 BE 00 80 43 00 8D BE 00 90 FC FF C7 87 D0 64 04 00 26 81 74 8D 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC }
    condition:
        $a at pe.entry_point

}
rule UPX_093_UnHack32_12: PEiD
{
    strings:
        $a = { 60 BE 00 A0 43 00 8D BE 00 70 FC FF C7 87 D0 84 04 00 98 C1 DF 2D 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC }
    condition:
        $a at pe.entry_point

}
rule Upx_v12_Marcus_Lazlo: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 05 A4 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 F2 31 C0 40 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 E6 31 C9 83 }
    condition:
        $a at pe.entry_point

}
rule UPX_Protector_v10x_2_additional: PEiD
{
    strings:
        $a = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }
    condition:
        $a at pe.entry_point

}
rule UPX_v062_DLL: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 58 }
    condition:
        $a at pe.entry_point

}
rule UPXFreak_v01_Borland_Delphi_HMX0101: PEiD
{
    strings:
        $a = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 }
        $b = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 34 50 45 00 ?? ?? ?? 00 FF FF 00 00 ?? 24 ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 40 00 00 C0 00 00 ?? ?? ?? ?? 00 00 ?? 00 00 00 ?? 1E ?? 00 ?? F7 ?? 00 A6 4E 43 00 ?? 56 ?? 00 AD D1 42 00 ?? F7 ?? 00 A1 D2 42 00 ?? 56 ?? 00 0B 4D 43 00 ?? F7 ?? 00 ?? F7 ?? 00 ?? 56 ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? 77 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 77 ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_Inliner_v10_by_GPcH: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 }
        $b = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 05 FF FF FF 85 C0 0F 84 06 03 00 00 89 85 C5 FE FF FF E8 00 00 00 00 5B B9 31 89 40 00 81 E9 2E 86 40 00 03 D9 50 53 E8 3D 02 00 00 61 03 BD A9 FE FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 09 FF FF FF FF B5 05 FF FF FF 56 57 FF 95 C5 FE FF FF 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB CE 68 00 80 00 00 6A 00 FF B5 C5 FE FF FF FF 95 09 FF FF FF 8D }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_070_PE: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 66 81 87 00 00 00 00 00 00 8D B0 EC 01 00 00 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
    condition:
        $a at pe.entry_point

}
rule UPX_Scrambler_by_GurueXe: PEiD
{
    strings:
        $a = { 66 C7 05 ?? ?? ?? ?? 75 07 E9 ?? FE FF FF 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_099_100_101_PE_DLL: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 00 00 00 00 60 BE AE 00 00 00 8D BE 52 00 00 FF 57 83 CD FF EB 0D 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC }
    condition:
        $a at pe.entry_point

}
rule UPX_v071_v072: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 ?? 60 BE 8D BE 57 83 CD }
        $b = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE FA ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 81 C6 B3 01 ?? ?? EB 0A ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_v0896_v102_v105_v122_DLL_Laszlo_Markus: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
    condition:
        $a at pe.entry_point

}
rule UPX_com_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B9 ?? ?? BE ?? ?? BF C0 FF FD }
    condition:
        $a at pe.entry_point

}
rule UPX_v062_Hint_WIN_EP: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 58 83 ?? ?? 50 8D ?? ?? ?? ?? ?? 57 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 ?? ?? 31 DB ?? ?? ?? EB }
    condition:
        $a at pe.entry_point

}
rule UPX_V200_V290_Markus_Oberhumer_Laszlo_Molnar_John_Reiser_additional: PEiD
{
    strings:
        $a = { FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        $a at pe.entry_point

}
rule UPX_v0896_v102_v105_v124_Markus_Laszlo_overlay: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 ?? 8B 1E 83 ?? ?? 11 DB 72 ?? B8 01 00 00 00 01 DB 75 }
    condition:
        $a at pe.entry_point

}
rule UPX_SCRAMBLER_306: PEiD
{
    strings:
        $a = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 BE ?? ?? ?? ?? 83 EC 04 89 34 24 B9 80 00 00 00 81 36 ?? ?? ?? ?? 50 B8 04 00 00 00 50 03 34 24 58 58 83 E9 03 E2 E9 EB D6 }
    condition:
        $a at pe.entry_point

}
rule UPXLock_v10_CyberDoom: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 60 E8 2B 03 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPXHiT_v001_additional: PEiD
{
    strings:
        $a = { 94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }
    condition:
        $a at pe.entry_point

}
rule UPX_Shit_01_500mhz: PEiD
{
    strings:
        $a = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 01 ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }
    condition:
        $a at pe.entry_point

}
rule UPX_v0896_v102_v105_v124_Markus_Laszlo_overlay_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 ?? 8B 1E 83 ?? ?? 11 DB 72 ?? B8 01 00 00 00 01 DB 75 }
    condition:
        $a at pe.entry_point

}
rule PseudoSigner_01_UPX_06_Anorganix: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9 }
    condition:
        $a at pe.entry_point

}
rule UPX_Shit_01_500mhz_additional: PEiD
{
    strings:
        $a = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 01 ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }
    condition:
        $a at pe.entry_point

}
rule UPX_Protector_v10x: PEiD
{
    strings:
        $a = { EB EC ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }
        $b = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_v060_v061_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 E8 }
    condition:
        $a at pe.entry_point

}
rule UPX_Shit_06_snaker: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? B9 15 00 00 00 80 34 08 ?? E2 FA E9 }
    condition:
        $a at pe.entry_point

}
rule UPX_v081_v084_Modified_additional: PEiD
{
    strings:
        $a = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF }
    condition:
        $a at pe.entry_point

}
rule UPX_050_070_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D }
    condition:
        $a at pe.entry_point

}
rule UPX_040_051_EXE: PEiD
{
    strings:
        $a = { 8C CB B9 00 00 BE 00 00 89 F7 1E A9 B5 80 8D 87 05 00 8E D8 05 00 00 8E C0 FD F3 A5 FC 2E 80 6C 13 10 73 E8 00 00 00 00 00 0E 0E 00 00 00 00 00 00 00 00 00 00 00 00 55 50 58 21 05 00 02 07 }
    condition:
        $a at pe.entry_point

}
rule UPX_081_083_EXE: PEiD
{
    strings:
        $a = { B9 00 00 BE 00 00 89 F7 1E A9 B5 80 8C C8 05 05 00 8E D8 05 00 00 8E C0 FD F3 A5 FC 2E 80 6C 12 10 73 E7 92 AF AD 0E 0E 0E 06 1F 07 16 BD 00 00 BB 00 80 55 CB 55 50 58 21 0A 03 03 07 }
    condition:
        $a at pe.entry_point

}
rule UPX_293_300_LZMA: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }
    condition:
        $a at pe.entry_point

}
rule UPX_v0761_pe_exe_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 57 83 ?? ?? 31 DB EB }
    condition:
        $a at pe.entry_point

}
rule UPX_200_30X_Markus_Oberhumer_Laszlo_Molnar_John_Reiser_additional: PEiD
{
    strings:
        $a = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF ?? ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 57 48 F2 AE 55 FF ?? ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB E1 FF ?? ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? ?? ?? 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        $a at pe.entry_point

}
rule UPX_293_LZMA_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }
    condition:
        $a at pe.entry_point

}
rule UPX_v081_v084_Modified_Laszlo_Markus: PEiD
{
    strings:
        $a = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF }
    condition:
        $a at pe.entry_point

}
rule UPX_v071_DLL_Hint_WIN_EP: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 83 }
    condition:
        $a at pe.entry_point

}
rule UPX_092_101_COM: PEiD
{
    strings:
        $a = { 81 FC 00 00 77 02 CD 20 B9 00 00 BE 00 00 BF 00 00 BB 00 80 FD F3 A4 FC 87 F7 83 EE C6 19 ED 57 57 E9 00 00 55 50 58 21 0B 01 04 07 00 00 00 00 00 00 00 00 00 00 00 00 06 00 FF FF }
    condition:
        $a at pe.entry_point

}
rule UPXFreak_V01_HMX0101_additional: PEiD
{
    strings:
        $a = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPXHiT_001_sibaway7yahoocom_additional: PEiD
{
    strings:
        $a = { E2 FA 94 FF E0 61 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_090_101_EXE: PEiD
{
    strings:
        $a = { B9 00 00 BE 00 00 89 F7 1E A9 B5 80 8C C8 05 05 00 8E D8 05 00 00 8E C0 FD F3 A5 FC 2E 80 6C 12 10 73 E7 92 AF AD 0E 0E 0E 06 1F 07 16 BD 00 00 BB 00 80 55 CB 55 50 58 21 0B 03 03 07 }
    condition:
        $a at pe.entry_point

}
rule UPX_v0896_v102_v105_v122_Delphi_stub: PEiD
{
    strings:
        $a = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 }
        $b = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_v30_EXE_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? 00 57 83 C3 04 53 68 ?? ?? ?? 00 56 }
    condition:
        $a at pe.entry_point

}
rule UPX_V200_V290_Markus_Oberhumer_amp_Laszlo_Molnar_amp_John_Reiser: PEiD
{
    strings:
        $a = { FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        $a at pe.entry_point

}
rule UPXcrypter_archphaseNWC_additional: PEiD
{
    strings:
        $a = { BF ?? ?? ?? 00 81 FF ?? ?? ?? 00 74 10 81 2F ?? 00 00 00 83 C7 04 BB 05 ?? ?? 00 FF E3 BE ?? ?? ?? 00 FF E6 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_v070_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 58 83 ?? ?? 50 8D ?? ?? ?? ?? ?? 57 66 ?? ?? ?? ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 83 ?? ?? 31 DB EB }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_UPX_06_Anorganix_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9 }
    condition:
        $a at pe.entry_point

}
rule UPX_v072_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 83 ?? ?? 31 DB 5E 8D ?? ?? ?? ?? ?? 57 66 ?? ?? ?? ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? EB }
    condition:
        $a at pe.entry_point

}
rule MSLRH_v032a_fake_UPX_0896_102_105_124_emadicius: PEiD
{
    strings:
        $a = { 60 BE 00 90 8B 00 8D BE 00 80 B4 FF 57 83 CD FF EB 3A 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 58 61 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
    condition:
        $a at pe.entry_point

}
rule UPX_062_EXE: PEiD
{
    strings:
        $a = { 8C CB B9 00 00 BE 00 00 89 F7 1E A9 B5 80 8D 87 05 00 8E D8 05 00 00 8E C0 FD F3 A5 FC 2E 80 6C 13 10 73 E8 00 00 00 00 00 0E 0E 00 00 00 00 00 00 00 00 00 00 00 CB 55 50 58 21 07 00 02 07 }
    condition:
        $a at pe.entry_point

}
rule UPX_7bit_Scrambler_102: PEiD
{
    strings:
        $a = { 0F 83 FA }
    condition:
        $a at pe.entry_point

}
rule UPX_092_094_PE_DLL: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 00 00 00 00 60 BE 2B 00 00 00 8D BE D5 00 00 FF 57 83 CD FF EB 0D 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC }
    condition:
        $a at pe.entry_point

}
rule UPX_081_084_PE_DLL: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 00 00 00 00 60 BE D9 00 00 00 8D BE 27 00 00 FF 57 83 CD FF EB 0D 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF 75 09 8B 1E 83 EE FC }
    condition:
        $a at pe.entry_point

}
rule VisualUPX_02_emadicius: PEiD
{
    strings:
        $a = { 66 C7 05 ?? ?? ?? 00 75 07 E9 ?? FE FF FF }
    condition:
        $a at pe.entry_point

}
rule Simple_UPX_Cryptor_v3042005_multi_layer_encryption_MANtiCORE: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? 00 B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
    condition:
        $a at pe.entry_point

}
rule UPX_Scrambler_RC_v1x_additional: PEiD
{
    strings:
        $a = { 66 C7 05 ?? ?? ?? ?? 75 07 E9 ?? FE FF FF 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_081_084_PE: PEiD
{
    strings:
        $a = { 60 BE 00 00 00 00 8D BE 00 00 00 FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 }
    condition:
        $a at pe.entry_point

}
rule UPX_v072: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 83 ?? ?? 31 DB 5E 8D ?? ?? ?? ?? ?? 57 66 ?? ?? ?? ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? EB }
    condition:
        $a at pe.entry_point

}
rule UPX_v070: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 83 CD FF 31 DB 5E 8D BE FA FF 57 66 81 87 81 C6 B3 01 EB 0A 8A 06 46 88 07 47 01 DB 75 }
        $b = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 EC 01 ?? ?? 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 07 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_v062_Laszlo_Markus: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 F0 01 ?? ?? 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 07 }
    condition:
        $a at pe.entry_point

}
rule UPXcrypter_archphaseNWC: PEiD
{
    strings:
        $a = { BF ?? ?? ?? 00 81 FF ?? ?? ?? 00 74 10 81 2F ?? 00 00 00 83 C7 04 BB 05 ?? ?? 00 FF E3 BE ?? ?? ?? 00 FF E6 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule Simple_UPX_Cryptor_v3042005_multi_layer_encryption_MANtiCORE_additional: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }
    condition:
        $a at pe.entry_point

}
rule UPX_v103_v104_Modified: PEiD
{
    strings:
        $a = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }
    condition:
        $a at pe.entry_point

}
rule VisualUPX_02_emadicius_additional: PEiD
{
    strings:
        $a = { 66 C7 05 ?? ?? ?? 00 75 07 E9 ?? FE FF FF }
    condition:
        $a at pe.entry_point

}
rule UPX_V200_V3X_Markus_Oberhumer_Laszlo_Molnar_John_Reiser: PEiD
{
    strings:
        $a = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF ?? ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 57 48 F2 AE 55 FF ?? ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB E1 FF ?? ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? ?? ?? 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        $a at pe.entry_point

}
rule UPXLock_v11_CyberDoom_Bob: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? 00 60 }
    condition:
        $a at pe.entry_point

}
rule UPX_v051: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 FF 57 8D B0 }
        $b = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 D8 01 ?? ?? 83 CD FF 31 DB ?? ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB 90 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPXFreak_V01_HMX0101: PEiD
{
    strings:
        $a = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_290_LZMA: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
        $b = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_v0761_pe_exe_Hint_WIN_EP: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 57 83 ?? ?? 31 DB EB }
    condition:
        $a at pe.entry_point

}
rule UPXShit_006_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }
    condition:
        $a at pe.entry_point

}
rule Simple_UPX_Cryptor_v3042005_One_layer_encryption_additional: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
    condition:
        $a at pe.entry_point

}
rule UPX_v103_v104_additional: PEiD
{
    strings:
        $a = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }
    condition:
        $a at pe.entry_point

}
rule UPX_062_PE: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 66 81 87 00 00 00 00 00 00 8D B0 F0 01 00 00 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB }
    condition:
        $a at pe.entry_point

}
rule UPX_v071_v072_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE FA ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 81 C6 B3 01 ?? ?? EB 0A ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }
    condition:
        $a at pe.entry_point

}
rule MSLRH_032a_fake_UPX_0896_102_105_124_emadicius: PEiD
{
    strings:
        $a = { 60 BE 00 90 8B 00 8D BE 00 80 B4 FF 57 83 CD FF EB 3A 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 58 61 90 EB 05 E8 EB 04 40 }
    condition:
        $a at pe.entry_point

}
rule UPX_v20_Markus_Laszlo_Reiser_h: PEiD
{
    strings:
        $a = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? 00 00 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 }
        $b = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? 00 00 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule _PseudoSigner_02_UPX_06: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_121_Markus_Laszlo: PEiD
{
    strings:
        $a = { 31 2E 32 31 00 55 50 58 }
    condition:
        $a at pe.entry_point

}
rule UPX_062_PE_DLL: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 58 83 E8 48 50 8D B8 00 00 00 FF 57 66 81 87 00 00 00 00 00 00 8D B0 F8 01 00 00 83 CD FF 31 DB EB 08 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 }
    condition:
        $a at pe.entry_point

}
rule UPX_V200_V290_Markus_Oberhumer_Laszlo_Molnar_John_Reiser: PEiD
{
    strings:
        $a = { FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_UPX_06: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9 }
    condition:
        $a at pe.entry_point

}
rule UPX_Inliner_v10_by_GPcH_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 }
    condition:
        $a at pe.entry_point

}
rule UPX_Shit_v01_500mhz_additional: PEiD
{
    strings:
        $a = { E8 00 00 00 00 5D 8B CD 81 ED 7A 29 40 00 89 AD 0F 6D 40 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_Modified_stub: PEiD
{
    strings:
        $a = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 ?? ?? ?? FF }
    condition:
        $a at pe.entry_point

}
rule UPX_Modifier_v01x_additional: PEiD
{
    strings:
        $a = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
    condition:
        $a at pe.entry_point

}
rule UPX_290_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90 }
        $b = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_v062: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 FF 57 66 81 87 8D B0 EC 01 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 }
        $b = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 F0 01 ?? ?? 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 07 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_Modified_Stub_c_Farb_rausch_Consumer_Consulting_: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2A 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 56 89 FE 29 C6 F3 A4 5E EB 9F 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 FF D3 11 C9 FF D3 72 F8 C3 31 C0 31 DB 31 C9 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F 0E 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 89 D8 E2 D9 8D BE ?? ?? ?? ?? 8B 07 09 C0 74 45 8B 5F 04 8D 84 30 ?? ?? ?? ?? 01 F3 50 83 C7 08 FF 96 ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 ?? ?? ?? ?? 61 E9 }
    condition:
        $a at pe.entry_point

}
rule Simple_UPX_Cryptor_v3042005_One_layer_encryption_MANtiCORE_additional: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
    condition:
        $a at pe.entry_point

}
rule UPX_v0896_v102_v105_v122_Modified_additional: PEiD
{
    strings:
        $a = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 }
    condition:
        $a at pe.entry_point

}
rule UPX_v0896_v102_v105_v122_Modified: PEiD
{
    strings:
        $a = { 01 DB 07 8B 1E 83 EE FC 11 DB 8A 07 EB B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }
        $b = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_v051_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 F0 01 ?? ?? 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 07 }
    condition:
        $a at pe.entry_point

}
rule UPXHiT_001_dj_siba: PEiD
{
    strings:
        $a = { 94 BC ?? ?? 43 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_Alternative_stub: PEiD
{
    strings:
        $a = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }
    condition:
        $a at pe.entry_point

}
rule UPX_293_300_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }
    condition:
        $a at pe.entry_point

}
rule Simple_UPX_Cryptor_v3042005_One_layer_encryption: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
    condition:
        $a at pe.entry_point

}
rule UPX_v103_v104: PEiD
{
    strings:
        $a = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }
        $b = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_071_072_EXE: PEiD
{
    strings:
        $a = { 8C CB B9 00 00 BE 00 00 89 F7 1E A9 B5 80 8D 87 05 00 8E D8 05 00 00 8E C0 FD F3 A5 FC 2E 80 6C 13 10 73 E8 00 00 00 00 00 0E 0E 00 00 00 00 00 00 00 00 00 00 00 CB 55 50 58 21 09 00 02 07 }
    condition:
        $a at pe.entry_point

}
rule UPX_Inliner_10_by_GPcH: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_02_UPX_06_Anorganix: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_0991_0993_PE_DLL: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 00 00 00 00 60 BE B0 00 00 00 8D BE 50 00 00 FF 57 83 CD FF EB 0D 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC }
    condition:
        $a at pe.entry_point

}
rule UPX_v0896_v102_v105_v122_DLL: PEiD
{
    strings:
        $a = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
        $b = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPXLock_v10_CyberDoom_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 60 E8 2B 03 00 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_122_Markus_Laszlo: PEiD
{
    strings:
        $a = { 31 2E 32 32 00 55 50 58 }
    condition:
        $a at pe.entry_point

}
rule UPX_SCRAMBLER_306_OnToL: PEiD
{
    strings:
        $a = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 BE ?? ?? ?? ?? 83 EC 04 89 34 24 B9 80 00 00 00 81 36 ?? ?? ?? ?? 50 B8 04 00 00 00 50 03 34 24 58 58 83 E9 03 E2 E9 EB D6 }
    condition:
        $a at pe.entry_point

}
rule UPX_082_083_COM: PEiD
{
    strings:
        $a = { 81 FC 00 00 77 02 CD 20 B9 00 00 BE 00 00 BF 00 00 BB 00 80 FD F3 A4 FC 87 F7 83 EE C6 19 ED 57 57 E9 00 00 55 50 58 21 0A 01 04 07 00 00 00 00 00 00 00 00 00 00 00 00 06 00 FF FF }
    condition:
        $a at pe.entry_point

}
rule UPX_290_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90 }
    condition:
        $a at pe.entry_point

}
rule SkD_Undetectabler_Pro_20_No_UPX_Method_SkD_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 B8 FC 26 00 10 E8 EC F3 FF FF 6A 0F E8 15 F5 FF FF E8 64 FD }
    condition:
        $a at pe.entry_point

}
rule UPX_V200_V300_Markus_Oberhumer_Laszlo_Molnar_John_Reiser: PEiD
{
    strings:
        $a = { FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        $a at pe.entry_point

}
rule UPX_v071_DLL: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 83 }
    condition:
        $a at pe.entry_point

}
rule UPX_v0761_dos_exe: PEiD
{
    strings:
        $a = { B9 ?? ?? BE ?? ?? 89 F7 1E A9 ?? ?? 8C C8 05 ?? ?? 8E D8 05 ?? ?? 8E C0 FD F3 A5 FC }
    condition:
        $a at pe.entry_point

}
rule UPX_Shit_05_snaker: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 83 F9 00 7E 06 80 30 ?? 40 E2 F5 E9 ?? ?? ?? FF }
    condition:
        $a at pe.entry_point

}
rule MSLRH_032a_fake_UPX_0896_102_105_124_emadicius_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 64 A0 23 00 00 00 83 C5 06 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 }
    condition:
        $a at pe.entry_point

}
rule UPXShit_006: PEiD
{
    strings:
        $a = { B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }
    condition:
        $a at pe.entry_point

}
rule UPX_070_EXE: PEiD
{
    strings:
        $a = { 8C CB B9 00 00 BE 00 00 89 F7 1E A9 B5 80 8D 87 05 00 8E D8 05 00 00 8E C0 FD F3 A5 FC 2E 80 6C 13 10 73 E8 00 00 00 00 00 0E 0E 00 00 00 00 00 00 00 00 00 00 00 CB 55 50 58 21 08 00 02 00 }
    condition:
        $a at pe.entry_point

}
rule UPX_v071_v072_Laszlo_Markus: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE FA ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 81 C6 B3 01 ?? ?? EB 0A ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }
    condition:
        $a at pe.entry_point

}
rule UPX_v070_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 58 83 ?? ?? 50 8D ?? ?? ?? ?? ?? 57 66 ?? ?? ?? ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 83 ?? ?? 31 DB EB }
    condition:
        $a at pe.entry_point

}
rule Simple_UPX_Cryptor_V3042005_MANtiCORE: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? ?? ?? ?? ?? E2 FA 61 68 ?? ?? ?? ?? C3 }
    condition:
        $a at pe.entry_point

}
rule Upx_v12_Marcus_Lazlo_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 05 A4 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 F2 31 C0 40 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 E6 31 C9 83 }
    condition:
        $a at pe.entry_point

}
rule UPX_v0896_v102_v105_v122_additional: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
    condition:
        $a at pe.entry_point

}
rule Password_Protector_for_the_UPX_030_g0d: PEiD
{
    strings:
        $a = { C8 50 01 00 60 E8 EC 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 44 69 61 6C 6F 67 42 6F 78 49 6E 64 69 72 65 63 74 50 61 72 61 6D 41 00 53 65 6E 64 4D 65 73 73 61 67 65 41 00 45 6E 64 44 69 61 6C 6F 67 00 00 00 55 8B EC 57 BF 00 00 00 00 33 C0 81 6D 0C 10 01 00 00 75 03 40 EB 13 83 7D 0C 01 75 0D 66 83 7D 10 0B 75 0B FF 75 14 8F 47 E4 5F 5D C2 10 00 66 83 7D 10 02 77 F4 74 0E 8D 4F A0 51 6A 40 6A 0D FF 77 E4 FF 57 E8 50 FF 75 08 FF 57 EC EB DB 84 08 C8 90 00 00 00 00 01 00 64 00 64 00 64 00 14 00 00 00 00 00 45 00 6E 00 74 00 65 00 72 00 20 00 50 00 61 00 73 00 73 00 77 00 6F 00 72 00 64 00 00 00 A0 00 00 50 00 00 02 00 05 00 05 00 5A 00 0A 00 0B 00 FF FF 81 00 00 00 00 00 5E FC 8D BE AA FE FF FF 8D 86 }
        $b = { C8 50 01 00 60 E8 EC 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 44 69 61 6C 6F 67 42 6F 78 49 6E 64 69 72 65 63 74 50 61 72 61 6D 41 00 53 65 6E 64 4D 65 73 73 61 67 65 41 00 45 6E 64 44 69 61 6C 6F }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_290_LZMA_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
    condition:
        $a at pe.entry_point

}
rule _PseudoSigner_01_UPX_06_Anorganix: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9 }
    condition:
        $a at pe.entry_point

}
rule UPX_Modified_Stub_c_Farb_rausch_Consumer_Consulting_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48 }
    condition:
        $a at pe.entry_point

}
rule UPX_wwwupxsourceforgenet: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? 00 8D BE ?? ?? ?? FF }
        $b = { 60 BE ?? ?0 ?? 00 8D BE ?? ?? F? FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule UPX_030_040_COM: PEiD
{
    strings:
        $a = { B9 00 00 BE 00 00 BF C0 FF BD FF FF FD F3 A4 FC F7 E1 93 87 F7 83 C6 00 57 }
    condition:
        $a at pe.entry_point

}
rule Unknown_UPX_modifyer_additional: PEiD
{
    strings:
        $a = { E8 02 00 00 00 CD 03 5A 81 C2 ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 89 D1 81 C1 3C 05 00 00 52 81 2A 33 53 45 12 83 C2 04 39 CA 7E F3 89 CA 8B 42 04 8D 18 29 02 BB 78 56 00 00 83 EA 04 3B 14 24 7D EC C3 }
    condition:
        $a at pe.entry_point

}
rule UPX_020_COM: PEiD
{
    strings:
        $a = { B9 00 00 BE 00 00 BF C0 FF BD FF FF FD F3 A4 FC F7 E1 93 87 F7 83 C6 31 57 57 E9 3C FE 55 50 58 21 03 01 02 87 }
    condition:
        $a at pe.entry_point

}
rule UPX_125_Markus_Laszlo: PEiD
{
    strings:
        $a = { 31 2E 32 35 00 55 50 58 }
    condition:
        $a at pe.entry_point

}
rule UPX_v0761_dos_exe_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B9 ?? ?? BE ?? ?? 89 F7 1E A9 ?? ?? 8C C8 05 ?? ?? 8E D8 05 ?? ?? 8E C0 FD F3 A5 FC }
    condition:
        $a at pe.entry_point

}
rule UPX_072: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E }
    condition:
        $a at pe.entry_point

}
rule UPXFreak_01_Borland_Delphi_HMX0101: PEiD
{
    strings:
        $a = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule Unknown_UPX_Scrambler_vna: PEiD
{
    strings:
        $a = { C7 45 FC ?? ?? ?? ?? 6A 04 6A 00 6A 00 68 FF FF FB FF FF 15 ?? ?? ?? ?? 85 C0 7E ?? 6A 00 FF 15 ?? ?? ?? ?? 8B 45 FC 8B 40 04 83 E8 03 8B 4D FC 89 41 04 83 65 F4 00 EB ?? 8B 45 F4 40 89 45 F4 8B 45 FC 8B 4D F4 3B 48 04 73 ?? 8B 45 FC 8B 40 04 2B 45 F4 8B 4D FC 8B 09 8B 55 FC 8B 44 01 FF 33 42 0C 8B 4D FC 8B 49 04 2B 4D F4 8B 55 FC 8B 12 89 44 11 FF EB ?? 8B 45 FC 8B 40 08 89 45 F8 8B 45 F8 }
    condition:
        $a at pe.entry_point

}
rule Unknown_UPX_or_File_modifyer: PEiD
{
    strings:
        $a = { E8 02 00 00 00 CD 03 5A 81 C2 86 EA FE FF 81 C2 45 23 01 00 89 D1 81 C1 3C 05 00 00 52 81 2A 33 53 45 12 83 C2 04 39 CA 7E F3 89 CA 8B 42 04 8D 18 29 02 BB 78 56 00 00 83 EA 04 3B 14 24 7D EC C3 }
    condition:
        $a at pe.entry_point

}
rule UPX_v062_DLL_Hint_WIN_EP: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 58 }
    condition:
        $a at pe.entry_point

}
rule UPX_051_072_COM: PEiD
{
    strings:
        $a = { B9 00 00 BE 00 00 BF C0 FF FD F3 A4 FC F7 E1 93 87 F7 83 EE 00 19 ED 57 }
    condition:
        $a at pe.entry_point

}