import "pe"

rule AMSIbypass_CLR_DLL{
    meta:
        id = "bf2ed8ea-db94-4025-a5d2-f65674acb8d9"
        yarahub_uuid = "c9c67fce-ff79-4e4b-a74d-b05b4b8ec78c"
        yarahub_license = "CC0 1.0"
        version = "1.0"
        malware = "Generic AMSI bypass"
        description = "AMSI bypass CLR. https://practicalsecurityanalytics.com/new-amsi-bypss-technique-modifying-clr-dll-in-memory/"
        yarahub_reference_link = "https://practicalsecurityanalytics.com/new-amsi-bypss-technique-modifying-clr-dll-in-memory/"
        source = "Sekoia.io"
        creation_date = "2025-02-28"
        date = "2025-02-28"
        classification = "TLP:WHITE"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        hash = "cd6f4fc883d86f2411809b3116629a9ef0a9f624acc31c7786db9f71dc07e5a0"
        yarahub_reference_md5 = "b30355dea8f4bcb58ac0fec0e4e1b72d"
    strings:
        $ = "EndsWith(\"clr.dll\"" ascii 
        $ = "$PAGE_READONLY = 0x02" ascii
        $ = "$PAGE_READWRITE = 0x04" ascii
        $ = "$PAGE_EXECUTE_READWRITE = 0x40" ascii
        $ = "$PAGE_EXECUTE_READ = 0x20" ascii
        $ = "$PAGE_GUARD = 0x100" ascii
        $ = "$MEM_COMMIT = 0x1000" ascii
        $ = "$MAX_PATH = 260" ascii
    condition:
        all of them
}

rule anyburn_iso_with_date {
    meta:
        author = "Nils Kuhnert"
        date = "2022-12-22"
        description = "Triggers on ISOs created with AnyBurn using volume names such as 12_19_2022."
        hash1_md5 = "e01931b3aba4437a92578dc802e5c41d"
        hash1_sha1 = "00799e6150e97f696635718d61f1a4f993994b87"
        hash1_sha256 = "87d51bb9692823d8176ad97f0e86c1e79d704509b5ce92b23daee7dfb2d96aaa"
        yarahub_reference_md5 = "e01931b3aba4437a92578dc802e5c41d"
        yarahub_author_twitter = "@0x3c7"
        yarahub_uuid = "0f217560-0380-458a-ac9a-d9d3065e22d9"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        $volume_name = { 43 44 30 30 31 01 00 00 57 00 69 00 6e 00 33 
                         00 32 00 20 00 20 00 20 00 20 00 20 00 20 00 20 
                         00 20 00 20 00 20 00 20 00 3? 00 3? 00 5f 00 3?
                         00 3? 00 5f 00 3? 00 3? 00 3? 00 3? 00 20 00 20 }
        $anyburn = "AnyBurn" wide fullword
    condition:
        all of them
}

rule AppLaunch
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing .Net AppLaunch.exe"
		example_file = "ba85b8a6507b9f4272229af0606356bab42af42f5ee2633f23c5e149c3fb9ca4"
		new_example_file = "cda99e504a122208862739087cf16b4838e9f051acfcbeb9ec794923b414c018"
		in_the_wild = true
		// yarahub data
		date = "2022-11-17"
		yarahub_uuid = "613f8ac7-a5f3-4167-bbcd-4dbfd4c8ba67"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "7dbfe0186e52ef2da13079f6d5b800d7"
	strings:
		$filelocation = "C:\\Windows\\Microsoft.NET\\Framewor"
		$applaunch = "\\AppLaunch.exe" nocase
	condition:
		$filelocation and $applaunch
}

rule APT_CN__Package2_DLL_April2024 {
    meta:
        Description = "Detects malware (Package 2) used by a Chinese APT targeting ASEAN entities"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://unit42.paloaltonetworks.com/chinese-apts-target-asean-entities/"
        File_Hash = "5cd4003ccaa479734c7f5a01c8ff95891831a29d857757bbd7fe4294f3c5c126"
        Info = "This malicious DLL part of the SCR (Package 2) which contains a legit executable, a malicious executable and this DLL"
        date = "2024-04-03"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "720eefb3a1c668f8befc2b365a369d76"
        yarahub_uuid = "7eddc35d-d621-45a3-ae84-f17067ddb9a9"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $str1 = "C:\\ProgramData\\updata" wide fullword
        $str2 = "estarmygame" wide

    condition:
        (pe.imphash() == "a069baeb4f8e125a451dc73aca6576b8"
        or (pe.imports("ADVAPI32.dll","RegCloseKey")
        and pe.imports("ADVAPI32.dll","RegOpenKeyExA")
        and pe.imports("KERNEL32.dll","IsProcessorFeaturePresent")
        and pe.imports("KERNEL32.dll","QueryPerformanceCounter")
        and pe.imports("KERNEL32.dll","IsDebuggerPresent")
        and pe.imports("ADVAPI32.dll","RegOpenKeyExA")
        and pe.imports("ADVAPI32.dll","RegSetValueExA")
        and pe.imports("SHELL32.dll","CommandLineToArgvW"))
        and pe.exports("RunServer"))
        and all of them

 }
 
 rule APT_CN__Package2_EXE_April2024 {
    meta:
        Description = "Detects malware (Package 2) used by a Chinese APT targeting ASEAN entities"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://unit42.paloaltonetworks.com/chinese-apts-target-asean-entities/"
        File_Hash = "02f4186b532b3e33a5cd6d9a39d9469b8d9c12df7cb45dba6dcab912b03e3cb8"
        Info = "This malicious EXE part of  SCR (Package 2) which contains a legit executable, a malicious DLL and this EXE"
        date = "2024-04-04"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "602d71d51d266c805b8afd4289851218"
        yarahub_uuid = "d4409ac0-feb8-44ae-bf55-48b43b49e300"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $str1 = "http://" wide fullword
        $str2 = "FWININET.DLL" wide fullword
        $str3 = "TKernel32.dll" wide fullword
        $str4 = "TComdlg32.dll" wide fullword

        $path1 = "C:\\Users\\Public\\EACore.dll" wide
        $path2 = "C:\\Users\\Public\\WindowsUpdate.exe" wide

        $url1 = "http://123.253.32.71/EACore.dll" wide
        $url2 = "http://123.253.32.71/WindowsUpdate.exe" wide

    condition:
        (pe.imphash() == "cf4236da1b59447c2fe49d31eb7bb6e2"
        or (pe.imports("UxTheme.dll","GetWindowTheme")
        and pe.imports("SHLWAPI.dll","PathIsUNCW")
        and pe.imports("MSIMG32.dll","AlphaBlend")
        and pe.imports("OLEACC.dll","AccessibleObjectFromWindow")
        and pe.imports("WINMM.dll","PlaySoundW")
        and pe.imports("ole32.dll","DoDragDrop")
        and pe.imports("ADVAPI32.dll","SystemFunction036")
        and pe.imports("SHELL32.dll","SHGetSpecialFolderLocation")
        and pe.imports("WINSPOOL.DRV","DocumentPropertiesW")))
        
        and (2 of ($str*)
        or any of ($path*)
        or any of ($url*))

 }
 
 
rule APT_Muddy_Water_MSI_RMM_Atera_April2024 {
    meta:
        Description = "Detects suspicious use of MSI Packages serving RMM Tool Atera used by APT Muddy Water in their Iron Swords Campaign"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://www.malwation.com/blog/new-muddywater-campaigns-after-operation-swords-of-iron"
        File_Hash = "ffbe988fd797cbb9a1eedb705cf00ebc8277cdbd9a21b6efb40a8bc22c7a43f0"
        Info = "Since RMM tools are legit, it might generate raise False Positives in your environment"
        date = "2024-04-04"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "4055d8b5c2e909f5db8b75a5750a7005"
        yarahub_uuid = "e296073f-e997-4462-ad51-a547c6924f0d"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $header = {d0	cf	11	e0	a1	b1	1a	e1} //MSI Header

        $msi1 = "msi.dll" fullword 
        $msi2 = "AVRemoteMsiSession@@" fullword

        $atera1 = "AteraAgent.exe" fullword
        $atera2 = "AteraAgentWD.exe" fullword
        $atera3 = "AteraNLogger.exe" fullword
        $atera4 = "AteraAgent" fullword

        $integrator = "eTuple.dll{38F01010-E311-4A27-8CA1-7D47222D9F74}BouncyCastle.Crypto.dll{B4CD9D10-FD72-430C-B045-A3113DECEB70}SetCustomActionPropertyValuesPostUninstallCleanupSKIPCLEANUP=[SKIPCLEANUP]PormptInstallationDialogShouldContinueInstallationPormptPreventUninstallDialogShouldPreventUninstallMyProcess.TaskKillCAQuietExecStopAteraServiceQuietWixQuietExecKillAteraTaskQuietKillAteraServicesc delete AteraAgentoldVersionUninstallunins000.exe /VERYSILENTinstall/i /IntegratorLogin=\"[INTEGRATORLOGIN]\" /CompanyId=\"[COMPANYID]\" /IntegratorLoginUI=\"[INTEGRATORLOGINUI]\" /CompanyIdUI=\"[COMPANYIDUI]\" /FolderId=\"[FOLDERID]\" /AccountId=\"[ACCOUNTID]\"uninstall/uDeleteTaskSchedulerSCHTASKS.EXE /delete /tn \"Monitoring Recovery\" /fWindowsFolderWINDOWSATERAwb3zdtk"
        
        $more1 = "AteraAgentProgramFilesFolder2rohim_f"
        $more2 = "ATERA Networks.SourceDirINSTALLFOLDER_files_Featureculrpfxg.exe"
        $more3 = "AteraAgent.exe1.8.6.707uho0yn3.con"
        $more4 = "AteraAgent.exe.configfd-i8f6f.dll"

    condition:
        $header at 0 
        and any of ($msi*)
        and any of ($atera*)
        and $integrator
        and any of ($more*)
        

}

rule apt_mustangpanda_poohloader
{
	meta:
		version = "1.0"
		author = "FatzQatz"
		description = "Detect PoohLoader, a Loader used by Mustang Panda to deploy Toneshell. This Loader utilized Mavinject to inject the shellcode."
		date = "2025-01-26"
		yarahub_reference_link = "https://x.com/FatzQatz/status/1883443770819248130"
		last_modified = "2025-01-26"
		yarahub_reference_md5 = "831fded4d56f7e1b04ad4384245ce874"
		yarahub_uuid = "cffc425e-baa3-4c69-a732-27e0e39f4b8e"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		falsepositives= "Unknown"
	strings:
		$s_1 = "C:\\Windows\\SysWOW64\\waitfor.exe" nocase wide
		$s_2 = "c:\\windows\\System32\\regsvr32.exe" nocase wide
		$s_3 = "C:\\Windows\\SysWOW64\\Mavinject.exe" nocase wide
		$s_4 = "DllRegisterServer" nocase
		$s_5 = "INJECTRUNNING" nocase wide
		$hex = {
			8B 45 F8			// mov     eax, [ebp+data_size]
			2B 45 EC			// sub     eax, [ebp+var_14]
			8B 4D EC			// mov     ecx, [ebp+var_14]
			8A 90 ?? ?? ?? ??	// mov     dl, ds:byte_mem1[eax]
			88 91 ?? ?? ?? ??	// mov     mem2[ecx], dl
			8B 45 F8			// mov     eax, [ebp+data_size]
			2B 45 EC			// sub     eax, [ebp+var_14]
			8A 4D E3			// mov     cl, [ebp+var_1D]
			88 88 ?? ?? ?? ??	// mov     ds:byte_mem1[eax], cl
	}
	condition:
		uint16(0) == 0x5A4D
		and (filesize >= 400KB and filesize <= 8MB)
		and (all of ($s_*)
			or (any of ($s_*) and $hex))
}

rule APT_Patchwork_Code_Signing_Cert_March2024 {
    meta:
        Description = "Detects malware used by Indian APT Patchwork based on the Code Signing Certificate"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://twitter.com/malwrhunterteam/status/1771152296933531982"
        Credits = "@malwrhunterteam for sharing the resuse of the certificate and references. @__0XYC__ and @ginkgo_g for sharing the malware hashes and attribution to APT"
        File_Hash = "8f4cf379ee2bef6b60fec792d36895dce3929bf26d0533fbb1fdb41988df7301"
        date = "2024-03-29"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "4f8bd643c59658e3d5b04d760073cbe9"
        yarahub_uuid = "1c970867-5a51-4243-9f0a-db802f28cc12"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        for any signature in pe.signatures:
            (signature.thumbprint == "424ef52be7acac19da5b8203494959a30b818f8d"
            or signature.issuer contains "CN=RUNSWITHSCISSORS LTD")
}

rule BatModifier1
{
    meta:
        author = "Madhav"
        description = "This is a bat file which is setup a game. 49509"
        date = "2025-05-10"
	yarahub_reference_md5 = "79a546f11d5ed65736735ba86cb95213"
	yarahub_uuid = "fb799bc3-fe63-40cd-804c-28a821d99c5b"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $mal1 = "PowerShell -Command \"Start-Process '%~f0' -Verb runAs\""
        $mal2 = "net session"
        $mal3 = "powershell -Command \"Invoke-WebRequest -Uri"
        $mal4 = "%SystemRoot%\\System32\\drivers\\etc\\hosts"
        $mal5 = "netsh advfirewall firewall add rule"
        $mal6 = "dir=out action=block remoteip="
	$mal7 = "%SystemRoot%\\System32\\curl.exe"
	$mal8 = "shell \"su -c 'id'\" | find \"uid=0(root)\""
	$mal9 = "tinyurl.com"
	$mal10 = "TaskKill /F /IM"
	$mal11 = "reg delete"
	$mal12 = "rd /s /q"
	$mal13 = "rd /q /s"
	$mal14 = "copy /y"
	$mal15 = "del /f"
	$mal16 = "del /s"
	$mal17 = "del /q"
    
    condition:
        all of ($mal1, $mal2, $mal3, $mal4, $mal5, $mal6, $mal7, $mal8) and
    	2 of ($mal9, $mal10, $mal11, $mal12, $mal13, $mal14, $mal15, $mal16, $mal17)
}

rule BatModifier2
{
    meta:
        author = "Madhav"
        description = "This is a bat file which is setup a game. 49509"
        date = "2025-05-10"
	yarahub_reference_md5 = "79a546f11d5ed65736735ba86cb95213"
	yarahub_uuid = "a4df6953-1e6f-488f-92c7-e06ab56ca848"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $mal1 = "PowerShell -Command \"Start-Process '%~f0' -Verb runAs\""
        $mal2 = "net session"
        $mal3 = "powershell -Command \"Invoke-WebRequest -Uri"
        $mal4 = "%SystemRoot%\\System32\\drivers\\etc\\hosts"
        $mal5 = "netsh advfirewall firewall add rule"
        $mal6 = "dir=out action=block remoteip="
	$mal7 = "%SystemRoot%\\System32\\curl.exe"
	$mal8 = "shell \"su -c 'id'\" | find \"uid=0(root)\""
	$mal9 = "tinyurl.com"
	$mal10 = "TaskKill /F /IM"
	$mal11 = "reg delete"
	$mal12 = "rd /s /q"
	$mal13 = "rd /q /s"
	$mal14 = "copy /y"
	$mal15 = "del /f"
	$mal16 = "del /s"
	$mal17 = "del /q"
    
    condition:
        5 of ($mal*)
}

rule BatModifier3
{
    meta:
        author = "Madhav"
        description = "This is a bat file which is setup a game. 49509"
        date = "2025-05-10"
	yarahub_reference_md5 = "79a546f11d5ed65736735ba86cb95213"
	yarahub_uuid = "40a63190-bedb-445f-ad61-bf142ed03ca3"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $mal1 = "PowerShell -Command \"Start-Process '%~f0' -Verb runAs\""

        $mal3 = "Invoke-WebRequest -Uri"
        $mal4 = "%SystemRoot%\\System32\\drivers\\etc\\hosts"
        $mal5 = "netsh advfirewall firewall add rule"

	$mal7 = "%SystemRoot%\\System32\\curl.exe"
	$mal8 = "shell \"su -c 'id'\""
	$mal15 = "uid=0(root)"
	$mal10 = "TaskKill /F /IM"
	$mal11 = "reg delete"
	$mal12 = "rd /"
	$mal13 = "copy /"
	$mal14 = "del /"
    
    condition:
        all of ($mal1, $mal3, $mal4, $mal5, $mal7) and 2 of ($mal8, $mal15, $mal10, $mal11, $mal12, $mal13, $mal14)
}

rule binaryObfuscation
{
  meta:
    author = 			"Sean Dalnodar"
    date = 			"2022-05-27"
    yarahub_uuid = 		"3f562951-b59f-4b27-806e-823e99910cac"
    yarahub_license =		"CC0 1.0"
    yarahub_rule_matching_tlp =	"TLP:WHITE"
    yarahub_rule_sharing_tlp = 	"TLP:WHITE"
    yarahub_reference_md5 =	"9c817fe677e2505306455d42d081252c"

  strings:
    $re0 = /=\([0-1,]{512}/

  condition:
    all of them
}

rule BrowserExtensionLoader {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-11-08"
        description = "Detects Chrome/Edge browser extension loader"
        yarahub_uuid = "9aa9f2aa-f3e3-4068-a7ca-17b89cfd03d4"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6c51dde7b67ecdd5b5ba4db58542a0a4"
    
    strings:
        $proc_chrome = "chrome.exe" wide ascii
        $proc_edge = "msedge.exe" wide ascii
        
        $cmd_kill = "taskkill /IM %s /F" wide ascii
        $cmd_load = "--load-extension" wide ascii
        $cmd_restore = "--restore-last-session" wide ascii
        
        $path_chrome = "\\AppData\\Local\\Google\\Chrome" wide ascii
        $path_chrome_beta = "\\AppData\\Local\\Google\\Chrome Beta" wide ascii
        $path_edge = "\\AppData\\Local\\Microsoft\\Edge" wide ascii
        
    condition:
        uint16(0) == 0x5a4d and
        (any of ($proc*) and 
        all of ($cmd*) and 
        any of ($path*))
}

rule cobalt_strike_tmp01925d3f {
	meta:
      description = "files - file ~tmp01925d3f.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-02-22"
      yarahub_reference_md5 = "1c6ba04dc9808084846ac1005deb9c85"
      yarahub_uuid = "58ae3b15-154e-47e9-a24c-c8b885a4cd55"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      hash1 = "10ff83629d727df428af1f57c524e1eaddeefd608c5a317a5bfc13e2df87fb63"
      score = 80
	strings:
      $x1 = "C:\\Users\\hillary\\source\\repos\\gromyko\\Release\\gromyko.pdb" fullword ascii
      $x2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s3 = "gromyko32.dll" fullword ascii
      $s4 = "<requestedExecutionLevel level='asInvoker' uiAccess='false'/>" fullword ascii
      $s5 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s6 = "https://sectigo.com/CPS0" fullword ascii
      $s7 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
      $s8 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
      $s9 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
      $s10 = "http://ocsp.sectigo.com0" fullword ascii
      $s11 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
      $s12 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
      $s13 = "http://www.digicert.com/CPS0" fullword ascii
      $s14 = "AppPolicyGetThreadInitializationType" fullword ascii
      $s15 = "alerajner@aol.com0" fullword ascii
      $s16 = "gromyko.inf" fullword ascii
      $s17 = "operator<=>" fullword ascii
      $s18 = "operator co_await" fullword ascii
      $s19 = "gromyko" fullword ascii
      $s20 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
	condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "1b1b73382580c4be6fa24e8297e1849d" or ( 1 of ($x*) or 4 of them ) )
}

rule CVE_2017_17215 {
    meta:
	author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-10-27"
        description = "Detects exploitation attempt of CVE-2017-17215"
        yarahub_uuid = "bd62321c-ccb7-4d6b-b98a-740aec5a452c"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a051d2730d19261621bd25d8412ba8e4"
	yarahub_reference_link = "https://nvd.nist.gov/vuln/detail/CVE-2017-17215"

    strings:
        $uri = "/ctrlt/DeviceUpgrade" ascii
        $digest_auth = "Digest username=" ascii
        $realm = "realm=\"" ascii
        $nonce = "nonce=" ascii
        $response = "response=" ascii

    condition:
        all of them
}

rule DelBat1
{
    meta:
        author = "Madhav"
        description = "This is a bat file which deletes the malicious file after the malicious files are executed"
        date = "2025-06-02"
	yarahub_reference_md5 = "0CCD4E0F8639AB3DB3C45B2768A41AFB"
	yarahub_uuid = "58ff8b5e-192e-4144-af8e-f29d282d1c70"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $mal1 = "chcp 65001"
        $mal2 = "del /a /q /f"
        $mal3 = "\\AppData\\Local\\Temp\\"
        $mal4 = ".exe"
        $mal5 = ".bat"
          
    condition:
        ($mal1 and $mal2 and $mal3 and $mal4 and $mal5) or ($mal2 and $mal3 and $mal4 and $mal5)
}

rule Detect_Dead_Family
{
    meta:
        description = "YARA rule for detecting files related to dead.dll family"
        author = "Your Name"
        date = "2025-01-14"
        family = "dead.dll"
        yarahub_uuid = "65069d71-1f5a-4394-bd79-0067ae7b60a4"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "5df15af3cff38a908d5807f8ee5f8055"

    strings:
        // Common strings from metadata or the file
        $filename = "dead.dll" ascii wide
        $productname = "dead" ascii wide
        $companyname = "dead" ascii wide
        $fileversion = "1.0.0.0" ascii wide
        
        // Common patterns in entry point or code
        $entry_point_pattern = { 48 89 4C 24 ?? 48 89 54 24 ?? 4C 89 44 24 ?? }

        // Section names
        $section_BOOT = "BOOT" ascii
        $section_INIT = "INIT" ascii
        $section_KERNEL = "KERNEL" ascii

    condition:
        uint16(0) == 0x5A4D and      // PE file signature
        filesize < 600000 and        // Allow similar file sizes, +/- range
        3 of ($filename, $productname, $companyname, $fileversion) and
        $entry_point_pattern and
        2 of ($section_BOOT, $section_INIT, $section_KERNEL)
}

rule Detect_Malicious_Python_Decompress_Exec {
    meta:
        description = "Detects malicious Python scripts with obfuscated zlib decompression and execution logic"
        author = "Sn0wFr0$t"
        reference = "Custom rule for obfuscated Python script detection"
        severity = "high"
		date = "2024-11-16"
		yarahub_uuid = "30413a55-c9cd-4b51-8944-1aec8eb95e66"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "b4916289881a8d13ad5230738bad3a6a"

    strings:
        $obfuscated_code = "_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));exec((_)("

    condition:
        $obfuscated_code
}

rule DetectGoMethodSignatures {
    meta:
        description = "Detects Go method signatures in unpacked Go binaries"
        author = "Wyatt Tauber"
        date = "2024-12-03"
        yarahub_reference_md5 = "c8820b30c0eddecf1f704cb853456f37"
        yarahub_uuid = "2a5e4bcf-3fcb-4bc9-9767-352e8d3307d6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        $go_signature = /[a-zA-Z_][a-zA-Z0-9_]*\.\(\*[a-zA-Z_][a-zA-Z0-9_]*\)\.[a-zA-Z_][a-zA-Z0-9_]*/

    condition:
        $go_signature
}

rule EXPLOIT_WinRAR_CVE_2023_38831_Aug23 {
    meta:
        version = "1.0"
        date = "2023-08-23"
        modified = "2023-08-23"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "SECUINFRA Falcon Team"
        author = "Marius Genheimer @ Falcon Team"
        description = "Detects ZIP archives potentially exploiting CVE-2023-38831 in WinRAR"
        category = "EXPLOIT"
        mitre_att = "T1203"
        actor_type = "CRIMEWARE"
        reference = "https://www.group-ib.com/blog/cve-2023-38831-winrar-zero-day"
        minimum_yara = "4.2"
        hash0 = "43f5eb815eed859395614a61251797aa777bfb694a9ef42fbafe058dff84d158"
        hash1 = "61c15d6a247fbb07c9dcbce79285f7f4fcc45f806521e86a2fc252a311834670"
        hash2 = "2010a748827129b926cf3e604b02aa77f5a7482da2a15350504d252ee13c823b"
        hash3 = "bfb8ca50a455f2cd8cf7bd2486bf8baa950779b58a7eab69b0c151509d157578"
        yarahub_uuid = "67176e05-1858-4ff4-ad4b-154f549ec5d4"
        yarahub_reference_md5 = "3a7ad5fdfc9e51c4ee5df425169add1a"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"

    strings:
        $kw_1 = "Trade" nocase ascii
        $kw_2 = "Trading" nocase ascii
        $kw_3 = "Strategy" nocase ascii
        $kw_4 = "Strategies" nocase ascii
        $kw_5 = "Screenshot" nocase ascii
        $kw_6 = "Indicator" nocase ascii

        $doubleext_cmd = {2E ?? ?? ?? 20 2E 63 6D 64}
        $doubleext_bat = {2E ?? ?? ?? 20 2E 62 61 74}
        $doubleext_vbs = {2E ?? ?? ?? 20 2E 76 62 73}
        $doubleext_wsf = {2E ?? ?? ?? 20 2E 77 73 66}
        $doubleext_wsh = {2E ?? ?? ?? 20 2E 77 73 68}
        $doubleext_ps1 = {2E ?? ?? ?? 20 2E 70 73 31}
        $doubleext_js = {2E ?? ?? ?? 20 2E 6A 73}

        $s_ico = ".ico" ascii

    condition:
        uint16(0) == 0x4B50
        and (any of ($kw_*) or none of ($kw_*))
        and any of ($doubleext_*)
        and #s_ico >= 1
}

rule garbled_obf_golang {
	meta:
        date = "2025-04-09"
		yarahub_reference_md5= "68b329da9893e34099c7d8ad5cb9c940"
        yarahub_uuid = "0c1c0fd8-6e61-4740-9626-bde9a82a13f0"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        // 004628aa  0fb6540448         movzx   edx, byte [rsp+rax+0x48 {var_40}]
        // 004628af  0fb6740449         movzx   esi, byte [rsp+rax+0x49 {var_40+0x1}]
        // 004628b4  89f7               mov     edi, esi
        // 004628b6  31d6               xor     esi, edx
        // 004628b8  8d3430             lea     esi, [rax+rsi]
        // 004628bb  8d76ed             lea     esi, [rsi-0x13]
        $ = { 0f b6 ?? ?? ?? 0f b6 ?? ?? ?? 89 f7 31 d6 8d ?? ?? ?? 8d ?? ?? }
    condition:
        all of them
}

rule globalnet_files
{
    meta:
        description = "Detect PE files compiled with PyInstaller with AntiDecompilation string. Observed in GlobalNet botnet campaign."
		reference = "https://twitter.com/vmovupd/status/1722548036839072017"
		author = "vmovupd"
		version = "1.0"
		date = "2024-01-28"
		yarahub_uuid = "e0280e2f-3fe8-4c11-b131-148d6b89cbde"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "96728cdb39ea05f8c8b1d80195a2914b"

    strings:
        $pyinst = {4D 45 49 0C 0B 0A 0B 0E}
		$antidecomp = "AntiDecompilation"
    condition:
        uint16(0) == 0x5A4D and $pyinst and $antidecomp
}

rule golang_bin_JCorn_CSC846 {

	meta:
		description = "CSC-846 Golang detection ruleset"
		author = "Justin Cornwell"
		date = "2024-12-09"
		yarahub_reference_md5 = "c8820b30c0eddecf1f704cb853456f37"
		yarahub_license = "CC0 1.0"
		yarahub_uuid = "b684bc3e-c106-4636-b9b7-f0a90e0b45d7"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
	strings:
		$string_go_build = "Go build" ascii wide
		$string_runtime = "runtime" ascii wide

	condition:
		uint16(0) == 0x5a4d // MZ header
		and any of them

}

rule Heuristics_ChromeCookieMonster {
	meta:
		author = "Still"
		component_name = "N/A"
		date = "2024-10-04"
		description = "attempts to match strings related to Chromium's CookieMonster; typically used in Chromium secrets scanning by stealers; heuristics rule - may match false positives"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "2EC23E83E2F63AB27C25741B1F4D7F49"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "06a64dd1-d590-442a-997f-000293fabc65"
	strings:
		$str_1 = "network.mojom.NetworkService" ascii wide 
		$str_2 = "chrome.dll" ascii wide
		$str_byte_pattern_1 = {56574883EC384889CE488B05AA}
		$str_byte_pattern_1_1 = "56574883EC384889CE488B05AA"
		$str_byte_pattern_1_2 = {
			C6 [2-6] 56
			C6 [2-6] 57
			C6 [2-6] 48
			C6 [2-6] 83
			C6 [2-6] EC
			C6 [2-6] 28
			C6 [2-6] 89
			C6 [2-6] D7
			C6 [2-6] 48
		}
		$str_byte_pattern_2 = {01 00 00 4C 8D 44 24 28 49 89 10 48}
		$str_byte_pattern_2_1 = "0100004C8D44242849891048"
		$str_byte_pattern_2_2 = {
			C6 [2-6] 01
			C6 [2-6] 00
			C6 [2-6] 00
			C6 [2-6] 4c
			C6 [2-6] 8d
			C6 [2-6] 44
			C6 [2-6] 24
			C6 [2-6] 28
			C6 [2-6] 49
			C6 [2-6] 89
		}
	/*
	0x140001862 33DB                          xor ebx, ebx
	0x140001864 488BF0                        mov rsi, rax
	0x140001867 4885C0                        test rax, rax
	0x14000186a 0F84B6000000                  je 140001926h
	0x140001870 4C8D4C2448                    lea r9, [rsp + 48h]
	0x140001875 C744242003000000              mov dword ptr [rsp + 20h], 3
	0x14000187d 448BC7                        mov r8d, edi
	0x140001880 488BD0                        mov rdx, rax
	0x140001883 488BCD                        mov rcx, rbp
	 */
		$inst_K32EnumProcessModulesEx = {
			33 DB
			48 8B F0
			48 85 C0
			0F 84 ?? ?? ?? ??
			4C 8D 4C 24 ??
			C7 44 24 ?? 03 00 00 00
			44 8B C7
			48 8B D0
			48 8B CD
		}
	/*
	0x140001af0 33C9                          xor ecx, ecx
	0x140001af2 85DB                          test ebx, ebx
	0x140001af4 7507                          jne 140001afdh
	0x140001af6 3D2B010000                    cmp eax, 12bh
	0x140001afb 7576                          jne 140001b73h
	0x140001afd 4C8B442438                    mov r8, qword ptr [rsp + 38h]
	0x140001b02 4D8BCE                        mov r9, r14
	0x140001b05 4C2BC5                        sub r8, rbp
	0x140001b08 4C2BCE                        sub r9, rsi
	0x140001b0b 4885ED                        test rbp, rbp
	 */
		$inst_scan_memory = {
			33 C9
			85 DB
			75 ??
			3D 2B 01 00 00
			75 ??
			4C 8B 44 24 ??
			4D 8B CE
			4C 2B C5
			4C 2B CE
			48 85 ED
		}
	condition:
		4 of ($str_*) or all of ($inst_*)
}

rule IDATDropper {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-07-30"
        description = "Detects files containing embedded JavaScript; the JS executes a PowerShell command which either downloads IDATLoader in an archive, or an executable (not IDATLoader) which is loaded into memory. The modified PE will only run if it's executed as an HTML Application (.hta)."
        yarahub_uuid = "9dbff40b-6257-438d-8932-e7fb652a4d6a"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "db1ae063d1be2bcb6af8f4afb145cdc4"
        yarahub_reference_link = "https://cyble.com/blog/increase-in-the-exploitation-of-microsoft-smartscreen-vulnerability-cve-2024-21412/"
        malpedia_family = "win.emmenhtal"
    
    strings:
        $hta = "HTA:APPLICATION" ascii
        
        $script_start = "<script>" ascii
        $variable = "var " ascii
        $decode_from_charcode = "String.fromCharCode" ascii
        $script_end = "</script>" ascii
        
    condition:
        all of them
}

rule ISO_LNK_JS_CMD_DLL {
   meta:
      description = "Detects iso > lnk > js > cmd > dll execution chain"
      author = "_jc"
      date = "2022-09-29"
      yarahub_reference_md5 = "b93bd94b8f568deac0143bf93f7d8bd8"
      yarahub_uuid = "3e54dac2-910d-4dda-a3b4-2fa052556be7"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
   strings:
      $lnk_header = { 4C 00 }
	  $minimized_inactive = {07}
	  $js_ext = ".js" nocase

	  $echo_off = { 40 65 63 68 6F [32-64] 33 32} // "@echo..32" to catch .cmd + regsvr32 stitching

	  $js_var = {76 61 72 [1-32] 3D [1-16] 3B} // catches javascript-style variable declaration

	  $mz_dos_mode = {4D 5A [100-110] 44 4F 53 20 6D 6F 64 65} // catches MZ..DOS Mode

   condition:
      // spot minimized_inactive flag; invocation of .js file by lnk
	  $echo_off and $js_var and $mz_dos_mode and
      for any i in (1..#lnk_header):
	  (($minimized_inactive in (@lnk_header[i]+60..@lnk_header[i]+61)) and ($js_ext in (@lnk_header[i]+255..@lnk_header[i]+304)))
}

rule LNK_Dropper_Russian_APT_Feb2024 {
    meta:
        Description = "Detects LNK dropper samples used by a Russian APT during a past campaign"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://blog.cluster25.duskrise.com/2024/01/30/russian-apt-opposition"
        Hash = "114935488cc5f5d1664dbc4c305d97a7d356b0f6d823e282978792045f1c7ddb"
        SampleTesting = "Matches all five LNK Dropper Samples from the Blog"
        date = "2024-02-05"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "b4f10039927b040f0470b956c74a31b4"
        yarahub_uuid = "569aa505-3cb6-4747-bbe6-38e6756ebd6e"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $pwrsh1 = "powershell.exe"
        $pwrsh2 = "WindowsPowerShell"
        $pwrsh3 = "powershell"
        $cmd = "cmd.exe"
        $ext1 = ".pdf.lnk" 
        $ext2 = ".pdfx.lnk"
        $ext3 = "pdf.lnk" base64
        $scrpt1 = "Select-String -pattern \"JEVycm9yQWN0aW9uUH\" "
        $scrpt2 = "findstr /R 'JVBERi0xLjcNJeLjz9'" base64
        $blob1 = "$ErrorActionPreference = \"Continue\"" base64
        $blob2 = "$ProgressPreference = \"SilentlyContinue\"" base64
        $blob3 = "New-Alias -name pwn -Value iex -Force" base64
        $blob4 = "if ($pwd.path.toLower() -ne \"c:\\windows\\system32\")" base64
        $blob5 = "Copy-Item $env:tmp\\Temp.jpg $env:userprofile\\Temp.jpg" base64
        $blob6 = "attrib +h $env:userprofile\\Temp.jpg" base64
        $blob7 = "Start-Process $env:tmp\\Important.pdf" base64
        $net1 = "$userAgent = \"Mozilla/6.4 (Windows NT 11.1) Gecko/2010102 Firefox/99.0\"" base64
        $net2 = "$redirectors = \"6" base64
        $net3 = "$sleeps = 5" base64
        $http1 = "$request.Headers[\"X-Request-ID\"] = $request_token" base64
        $http2 = "$request.ContentType = \"application/x-www-form-urlencoded\"" base64
        $http3 = "$response1 = $(Send-HttpRequest \"$server/api/v1/Client/Info\" \"POST\" \"Info: $getenv64\")" base64
        $http4 = "$response = $($token = Send-HttpRequest \"$server/api/v1/Client/Token\" \"GET\")" base64
        $server1 = "$server = \"api-gate.xyz\"" base64
        $server2 = "$server = \"pdf-online.top\"" base64
        $unknown = "$server = " base64
        
    condition:
        $lnk at 0                       //LNK File Header
        and (any of ($pwrsh*) or $cmd) //searches for CMD or PowerShell execution 
        and any of ($ext*)            //Fake Double Extension mimicing a PDF
        and any of ($scrpt*)         //Searches for a unique string to locate execution code
        and 5 of ($blob*)           //Base64 encoded execution blob
        and 2 of ($net*) 
        and 3 of ($http*)
        and (any of ($server*) or $unknown) // C2 dommain config (Optional, can be removed)
        
 }

rule lnk_from_chinese : odd {
    meta:
        category = "apt"
        description = "what the rule does"
        author = "malcat"
        reliability = 50
        date = "2022-07-04"
        yarahub_uuid = "17a4f2d6-0792-45de-8b90-749bec1bcc18"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e3f89049dc5f0065ee4d780f8aef9c04"
    strings:
        $magic = { 4C0000000114020000000000C000000000000046 }
        $serial = {90962EBA}
    condition:
        $magic at 0 and $serial
}

rule meth_get_eip {
  meta:
    date = "2022-06-13"
    author = "Willi Ballenthin"
    yarahub_author_email = "william.ballenthin@mandiant.com"
    yarahub_author_twitter = "@williballenthin"
    yarahub_uuid = "666bfd55-7931-454e-beb8-22b5211ab04f"
    yarahub_license = "CC BY 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "9727d5c2a5133f3b6a6466cc530a5048"
    strings:
       // 0:  e8 00 00 00 00          call   5 <_main+0x5>
       // 5:  58                      pop    eax
       // 6:  5b                      pop    ebx
       // 7:  59                      pop    ecx
       // 8:  5a                      pop    edx
       // 9:  5e                      pop    esi
       // a:  5f                      pop    edi
       $x86 = { e8 00 00 00 00 (58 | 5b | 59 | 5a | 5e | 5f) }

    condition:
       $x86
}

rule meth_peb_parsing {
  meta:
    date = "2022-06-13"
    author = "Willi Ballenthin"
    yarahub_author_email = "william.ballenthin@mandiant.com"
    yarahub_author_twitter = "@williballenthin"
    yarahub_uuid = "fc096806-e637-43ac-b969-ec6a1f37328a"
    yarahub_license = "CC BY 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "00000000000000000000000000000000"
    strings:
       //                                                         ;; TEB->PEB
       // (64 a1 30 00 00 00 |                                    ; mov eax, fs:30
       //  64 8b (1d | 0d | 15 | 35 | 3d) 30 00 00 00 |           ; mov $reg, DWORD PTR fs:0x30
       //  31 (c0 | db | c9 | d2 | f6 | ff) [0-8] 64 8b ?? 30 )   ; xor $reg; mov $reg, DWORD PTR fs:[$reg+0x30]
       // [0-8]                                                   ; up to 8 bytes of interspersed instructions
       //                                                         ;; PEB->LDR_DATA
       // 8b ?? 0c                                                ; mov eax,DWORD PTR [eax+0xc]
       // [0-8]                                                   ; up to 8 bytes of interspersed instructions
       //                                                         ;; LDR_DATA->OrderLinks
       // 8b ?? (0c | 14 | 1C)                                    ; mov edx, [edx+0Ch]
       // [0-8]                                                   ; up to 8 bytes of interspersed instructions
       //                                                         ;; _LDR_DATA_TABLE_ENTRY.DllName.Buffer
       // 8b ?? (28 | 30)                                         ; mov esi, [edx+28h]
       $peb_parsing = { (64 a1 30 00 00 00 | 64 8b (1d | 0d | 15 | 35 | 3d) 30 00 00 00 | 31 (c0 | db | c9 | d2 | f6 | ff) [0-8] 64 8b ?? 30 ) [0-8] 8b ?? 0c [0-8] 8b ?? (0c | 14 | 1C) [0-8] 8b ?? (28 | 30) }

       $peb_parsing64 = { (48 65 A1 60 00 00 00 00 00 00 00 | 65 (48 | 4C) 8B ?? 60 00 00 00 | 65 A1 60 00 00 00 00 00 00 00 | 65 8b ?? ?? 00 FF FF | (48 31 (c0 | db | c9 | d2 | f6 | ff) | 4D 31 (c0 | c9))  [0-16] 65 (48 | 4d | 49 | 4c) 8b ?? 60) [0-16] (48 | 49 | 4C) 8B ?? 18 [0-16] (48 | 49 | 4C) 8B ?? (10 | 20 | 30) [0-16] (48 | 49 | 4C) 8B ?? (50 | 60) }

    condition:
       $peb_parsing or $peb_parsing64
}

rule meth_stackstrings {
  meta:
    date = "2022-06-13"
    author = "Willi Ballenthin"
    yarahub_author_email = "william.ballenthin@mandiant.com"
    yarahub_author_twitter = "@williballenthin"
    yarahub_uuid = "71fe67dc-8cb3-4b1f-8eb8-7b2e0933e0b4"
    yarahub_license = "CC BY 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "00000000000000000000000000000000"
    strings:
        // stack string near the frame pointer.
        // the compiler may choose to use a single byte offset from $bp.
        // like: mov [ebp-10h], 25h
        //
        // regex explanation:
        //   4 times:
        //     byte C6          (mov byte)
        //     byte 45          ($bp-relative, one-byte offset)
        //     any byte         (the offset from $bp)
        //     printable ascii  (the immediate constant)
        //   1 times:
        //     byte C6          (mov byte)
        //     byte 45          ($bp-relative, one-byte offset)
        //     any byte         (the offset from $bp)
        //     byte 00          (the immediate constant, null terminator)
        $ss_small_bp = /(\xC6\x45.[a-zA-Z0-9 -~]){4,}\xC6\x45.\x00/

        // dword stack string near the frame pointer.
        // the compiler may choose to use a single byte offset from $bp.
        // it may move four bytes at a time onto the stack.
        // like: mov [ebp-10h], 680073h  ; "sh"
        //
        // regex explanation:
        //   2 times:
        //     byte C7          (mov dword)
        //     byte 45          ($bp-relative, one-byte offset)
        //     any byte         (the offset from $bp)
        //     printable ascii  (the immediate constant)
        //     byte 00          (second byte of utf-16 encoding of ascii character)
        //     printable ascii  (the immediate constant)
        //     byte 00          (second byte of utf-16 encoding of ascii character)
        //   1 times:
        //     byte C7          (mov dword)
        //     byte 45          ($bp-relative, one-byte offset)
        //     any byte         (the offset from $bp)
        //     any byte         (immediate constant or NULL terminator)
        //     byte 00          (the immediate constant, NULL terminator)
        //     byte 00          (the immediate constant, NULL terminator)
        //     byte 00          (the immediate constant, NULL terminator)
        $ss_small_bp_dword = /(\xC7\x45.[a-zA-Z0-9 -~]\x00[a-zA-Z0-9 -~]\x00){2,}\xC7\x45..\x00\x00\x00/

        // stack strings further away from the frame pointer.
        // the compiler may choose to use a four-byte offset from $bp.
        // like: mov byte ptr [ebp-D80h], 5Ch
        // we restrict the offset to be within 0xFFF (4095) of the frame pointer.
        //
        // regex explanation:
        //   4 times:
        //     byte C6          (mov byte)
        //     byte 85          ($bp-relative, four-byte offset)
        //     any byte         (LSB of the offset from $bp)
        //     byte 0xF0-0xFF   (second LSB of the offset from $bp)
        //     byte FF          (second MSB)
        //     byte FF          (MSB of the offset from $bp)
        //     printable ascii  (the immediate constant)
        //   1 times:
        //     byte C6          (mov byte)
        //     byte 85          ($bp-relative, four-byte offset)
        //     any byte         (LSB of the offset from $bp)
        //     byte 0xF0-0xFF   (second LSB of the offset from $bp)
        //     byte FF          (second MSB)
        //     byte FF          (MSB of the offset from $bp)
        //     byte 00          (the immediate constant, null terminator)
        $ss_big_bp = /(\xC6\x85.[\xF0-\xFF]\xFF\xFF[a-zA-Z0-9 -~]){4,}\xC6\x85.[\xF0-\xFF]\xFF\xFF\x00/

        // stack string near the stack pointer.
        // the compiler may choose to use a single byte offset from $sp.
        // like: mov byte ptr [esp+0Bh], 24h
        //
        // regex explanation:
        //   4 times:
        //     byte C6          (mov byte)
        //     byte 44          ($sp-relative, one-byte offset)
        //     byte 24          ($sp-relative, one-byte offset)
        //     any byte         (the offset from $sp)
        //     printable ascii  (the immediate constant)
        //   1 times:
        //     byte C6          (mov byte)
        //     byte 44          ($sp-relative, one-byte offset)
        //     byte 24          ($sp-relative, one-byte offset)
        //     any byte         (the offset from $sp)
        //     byte 00          (the immediate constant, null terminator)
        $ss_small_sp = /(\xC6\x44\x24.[a-zA-Z0-9 -~]){4,}\xC6\x44\x24.\x00/

        // stack strings further away from the stack pointer.
        // the compiler may choose to use a four-byte offset from $sp.
        // like: byte ptr [esp+0DDh], 49h
        // we restrict the offset to be within 0xFFF (4095) of the stack pointer.
        //
        // regex explanation:
        //   4 times:
        //     byte C6          (mov byte)
        //     byte 84          ($sp-relative, four-byte offset)
        //     byte 24          ($sp-relative, four-byte offset)
        //     any byte         (LSB of the offset from $sp)
        //     byte 0x00-0x0F   (second LSB of the offset from $sp)
        //     byte 00          (second MSB)
        //     byte 00          (MSB of the offset from $sp)
        //     printable ascii  (the immediate constant)
        //   1 times:
        //     byte C6          (mov byte)
        //     byte 84          ($sp-relative, four-byte offset)
        //     byte 24          ($sp-relative, four-byte offset)
        //     any byte         (LSB of the offset from $sp)
        //     byte 0x00-0x0F   (second LSB of the offset from $sp)
        //     byte 00          (second MSB)
        //     byte 00          (MSB of the offset from $sp)
        //     byte 00          (the immediate constant, null terminator)
        $ss_big_sp = /(\xC6\x84\x24.[\x00-\x0F]\x00\x00[a-zA-Z0-9 -~]){4,}\xC6\x84\x24.[\x00-\x0F]\x00\x00\x00/

    condition:
        $ss_small_bp or $ss_small_bp_dword or $ss_big_bp or $ss_small_sp or $ss_big_sp
}

rule Old_Code__Signature_AnyDesk_Feb2024 {
    meta:
        Description = "Detects files with older and no longer valid code signing certifcates of AnyDesk"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Inspired by Florian Roth"
        Reference = "https://twitter.com/cyb3rops/status/1753440743480238459"
        Goodware_Hash = "55e4ce3fe726043070ecd7de5a74b2459ea8bed19ef2a36ce7884b2ab0863047"
        date = "2024-02-03"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "a21768190f3b9feae33aaef660cb7a83"
        yarahub_uuid = "fa45b9a9-0db8-4b3a-b60e-f6eb7bc01f0f"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    
    condition:
        pe.version_info["CompanyName"] contains "AnyDesk"
        and for 2 signature in pe.signatures:
        (signature.thumbprint != "646f52926e01221c981490c8107c2f771679743a") //Latest AnyDesk Code Sign Cert
       
}
 
rule PassProtected_ZIP_ISO_file {
   meta:
      description = "Detects container formats commonly smuggled through password-protected zips"
      author = "_jc"
      date = "2022-09-29"
      yarahub_reference_md5 = "b93bd94b8f568deac0143bf93f7d8bd8"
      yarahub_uuid = "0b027752-0217-48f9-9515-3760872cc210"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
   strings:
      $password_protected_zip = { 50 4B 03 04 14 00 01 }

      $container_1 = ".iso" ascii
      $container_2 = ".rr0" ascii
      $container_3 = ".img" ascii
      $container_4 = ".vhd" ascii
      $container_5 = ".rar" ascii

   condition:
      uint32(0) == 0x04034B50 and
      filesize < 2000KB and 
      $password_protected_zip and 
      1 of ($container*)
}

rule pe_detect_tls_callbacks {

    meta:
        date = "2024-07-26"
        yarahub_uuid = "881c8cad-35ef-414d-8906-0f98f7b37cd6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "13794d1d8e87c69119237256ef068043"

     condition:
        uint16(0) == 0x5a4d and pe.data_directories[9].virtual_address != 0 and  pe.data_directories[9].size != 0
}

rule pe_packer_pecompact2 {
    meta:
        date = "2023-09-07"
        yarahub_uuid = "8f58ee66-b658-4720-a986-4916308812d1"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "b204bee0440f1d7b82c64107610ea9b5"
        desc = "Detects PECompact2"
        author = "@jstrosch"

    strings:

        /*
            CODE:00401000 B8 74 C4 45 00       mov     eax, offset loc_45C474
            CODE:00401005 50                   push    eax
            CODE:00401006 64 FF 35 00 00 00 00 push    large dword ptr fs:0
            CODE:0040100D 64 89 25 00 00 00 00 mov     large fs:0, esp
            CODE:00401014 33 C0                xor     eax, eax
            CODE:00401016 89 08                mov     [eax], ecx
        */

        $x1 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 }
        $s1 = "PECompact2"

    condition:
         uint16(0) == 0x5a4d and $x1 at pe.entry_point and $s1 in (1024..1056) 
}

rule PNG_File_Malware_Abuse {
    meta:
        description = "Detects malicious PNG files leveraging this technique"
        author = "d1v35h"
        date = "2025-01-02"
        yarahub_reference_md5 = "a9053a6606748a87a135b942eb47a8c0"
	yarahub_uuid = "f7e0a82d-3a34-4f47-bd19-20db5643ab16"
	yarahub_license	= "CC0 1.0"
	yarahub_rule_matching_tlp = "TLP:WHITE"
	yarahub_rule_sharing_tlp = "TLP:WHITE"
	malpedia_family	= "win.netsupportmanager_rat"
    strings:
        $png_header = { 69 70 63 6f 6e 66 69 67 20 2f 66 6c 75 73 68 64 6e 73 0d }  
        $powershell_indicator = "powershell.exe"
        $exe = "client32.exe"
    condition:
        $png_header at 0 and (1 of ($powershell_indicator, $exe))
}

rule Powerpoint_Code_Execution {

	meta:

		author = "Ahmet Payaslioglu"
		yarahub_author_twitter = "@Computeus7"
		date = "2022-09-15"
		description ="New code execution technique using Powerpoint has been seen in the wild. The technique is triggered by using hyperlinks instead of Run Program/Macro. This new method has bypassed all the vendors for 220 days since 2022-02-02."
		yarahub_reference_md5 = "c0060c0741833af67121390922c44f91"
		yarahub_reference_link = "https://www.linkedin.com/feed/update/urn:li:activity:6976093476027314176/" 
		yarahub_uuid = "9582d920-9bc4-4db3-9048-54ea56567dbd"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"


	strings:

		$a1 = {D0 CF 11 E0 A1 B1 1A E1} //header

		$b1 = {6C 00 6F 00 63 00 61 00 6C 00 2E 00 6C 00 6E 00 6B} //local.lnk

		$b2 = {6C 00 6D 00 61 00 70 00 69 00 32 00 2E 00 64 00 6C 00 6C 00} //lmapi2.dll

		$b3 = {72 00 75 00 6E 00 64 00 6C 00 6C 00 33 00 32} //rundll32.exe

		$b4 = {4E 00 65 00 74 00 2E 00 57 00 65 00 62 00 43 00 6C 00 69 00 65 00 6E 00 74 00 29 00 2E 00 44 00 6F 00 77 00 6E 00 6C 00 6F 00 61 00 64 00 44 00 61 00 74 00 61} //Net Web Client) Download Data

	condition:
		($a1 at 0) and (4 of ($b*)) and filesize < 2MB
}

rule Runtime_Broker_Variant_1 {
   meta:
      description = "Detecting malicious Runtime Broker"
      author = "Sn0wFr0$t"
      date = "2025-06-01"
      yarahub_uuid = "2de96c5f-876b-4ebb-b7a3-60900c6dab62"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_reference_md5 = "1450d7c122652115ef52febfa9e59349"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide
      $s2 = "!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii
      $s3 = "mscordaccore.dll" fullword wide
      $s4 = "Runtime Broker.dll" fullword wide 
      $s5 = "D:\\a\\_work\\1\\s\\artifacts\\obj\\coreclr\\windows.x64.Release\\dlls\\mscordac\\mscordaccore.pdb" fullword ascii 
      $s6 = "Runtime Broker - Windows NT Mode" fullword wide 
      $s7 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii 
      $s8 = "ni.dll" fullword wide 
      $s9 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii 
      $s10 = "PROCESSOR_COUNT" fullword wide 
      $s11 = "Nhttp://www.microsoft.com/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1).crl0l" fullword ascii
      $s12 = "Phttp://www.microsoft.com/pkiops/certs/Microsoft%20Time-Stamp%20PCA%202010(1).crt0" fullword ascii 
      $s13 = "!-- Windows 7 -->" fullword ascii 
      $s14 = "!-- Windows Vista -->" fullword ascii
      $s15 = "      \"Microsoft.Extensions.DependencyInjection.VerifyOpenGenericServiceTrimmability\": true," fullword ascii
      $s16 = "!-- Windows 8 -->" fullword ascii
      $s17 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii
      $s18 = "!-- Windows 10 -->" fullword ascii
      $s19 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii
      $s20 = "longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule Runtime_Broker_Variant_2 {
   meta:
      description = "Detecting malicious Runtime Broker"
      author = "Sn0wFr0$t"
      date = "2025-06-01"
      yarahub_uuid = "e820a014-bf4b-40ed-b9ce-2d7f5d3571f0"
	  yarahub_license = "CC0 1.0"
	  yarahub_rule_matching_tlp = "TLP:WHITE"
	  yarahub_rule_sharing_tlp = "TLP:WHITE"
	  yarahub_reference_md5 = "9245cdd50168dcf0115ab60324114c07"
   strings:
      $x1 = "C:\\Users\\user\\Desktop\\DotNetTor\\src\\DotNetTor\\obj\\Release\\netstandard2.0\\DotNetTor.pdb" fullword ascii
      $s2 = "ESystem.Net.Http.HttpMessageHelper+<GetDecodedChunkedContentAsync>d__5" fullword ascii
      $s3 = "ESystem.Net.Http.HttpMessageHelper+<GetDecodedChunkedContentAsync>d__7" fullword ascii
      $s4 = "ESystem.Net.Http.HttpMessageHelper+<GetDecodedChunkedContentAsync>d__6" fullword ascii
      $s5 = "BSystem.Net.Http.HttpMessageHelper+<GetContentTillLengthAsync>d__11" fullword ascii
      $s6 = "7System.Net.Http.HttpMessageHelper+<GetContentAsync>d__3" fullword ascii
      $s7 = "7System.Net.Http.HttpMessageHelper+<GetContentAsync>d__4" fullword ascii 
      $s8 = "DotNetTor.dll" fullword wide
      $s9 = "?System.Net.Http.HttpMessageHelper+<GetContentTillEndAsync>d__10" fullword ascii
      $s10 = "8System.Net.Http.HttpMessageHelper+<ReadHeadersAsync>d__1" fullword ascii 
      $s11 = "Failed to send command to TOR Control Port: {0} : {1}" fullword wide 
      $s12 = "4DotNetTor.ControlPort.Client+<SendCommandAsync>d__15" fullword ascii 
      $s13 = "4DotNetTor.ControlPort.Client+<SendCommandAsync>d__16" fullword ascii 
      $s14 = "HttpResponseContentHeaders" fullword ascii 
      $s15 = "HttpRequestContentHeaders" fullword ascii 
      $s16 = "<GetDecodedChunkedContentAsync>d__7" fullword ascii 
      $s17 = "ASystem.Net.Http.HttpResponseMessageExtensions+<ToStreamAsync>d__1" fullword ascii 
      $s18 = "ASystem.Net.Http.HttpMessageHelper+<ReadBytesTillLengthAsync>d__12" fullword ascii 
      $s19 = "BSystem.Net.Http.HttpResponseMessageExtensions+<CreateNewAsync>d__0" fullword ascii
      $s20 = "ASystem.Net.Http.HttpRequestMessageExtensions+<CreateNewAsync>d__0" fullword ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule ScanStringsInsocks5systemz {
	meta:
		description = "Scans presence of the found strings using the in-house brute force method"
		author = "Byambaa@pubcert.mn"
		date = "2024-10-01"
        	yarahub_uuid = "cd061b79-9264-480a-bda6-2242046143d5"
        	yarahub_license = "CC0 1.0"
        	yarahub_rule_matching_tlp = "TLP:WHITE"
        	yarahub_rule_sharing_tlp = "TLP:WHITE"
        	yarahub_reference_md5 = "73875E9DA68182B09BC6A7FAAFFF67D8"
	strings:
		$string0 = "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)"
		$string1 = "$*@@@*$@@@$ *@@* $@@($*)@-$*@@$-*@@$*-@@(*$)@-*$@@*-$@@*$-@@-* $@-$ *@* $-@$ *-@$ -*@*- $@($ *)(* $)U"
	condition:
		any of them
	}

rule SelfExtractingRAR {
  meta:
    author = "Xavier Mertens"
    description = "Detects an SFX archive with automatic script execution"
    date = "2023-05-17"
    yarahub_author_twitter = "@xme"
    yarahub_author_email = "xmertens@isc.sans.edu"
    yarahub_reference_link = "https://isc.sans.edu/diary/rss/29852"
    yarahub_uuid = "bcc4ceab-0249-43af-8d2a-8a04d5c65c70"
    yarahub_license =  "CC0 1.0"
    yarahub_rule_matching_tlp =  "TLP:WHITE"
    yarahub_rule_sharing_tlp =  "TLP:WHITE"
    yarahub_reference_md5= "7792250c87624329163817277531a5ef" 

    strings:
        $exeHeader = "MZ"
        $rarHeader = "Rar!" wide ascii
        $sfxSignature = "SFX" wide ascii
        $sfxSetup = "Setup=" wide ascii

    condition:
       $exeHeader at 0 and $rarHeader and $sfxSignature and $sfxSetup
}

rule sfx_pdb_winrar_restrict {

   meta:
      author = "@razvialex"
      description = "Detect interesting files containing sfx with pdb paths."
      date = "2022-07-12"
      yarahub_author_twitter = "@razvialex"
      yarahub_reference_md5 = "826108ccdfa62079420f7d8036244133"
      yarahub_uuid = "8835c09d-0b29-4892-8c68-fd520de87bd6"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"

   strings:
      $var1 = {0D786FA11A6028825A871437B4A067DF66AD67D833A5F938FE6EC930FD51CEF76D711BE7F24D203888A458DFC627FBFCAC32B8D15C96EC7722BB84E4A718812C4BB7A76563E2E43413E3A98A8AE4BA7DBA019CDBF07B3D4434E69B3C6DBC46D120ABB2F78192F0674CFEF4AA8EC682B5EA7C3F995610AA1C2B60F1BA730EC29BF769CFDE5AED1FA0A2479888B08F149C38AAE726B742E5}
      $var2 = "E<ul><li>Press <b>Install</b> button to start extraction.</li><br><br>E<ul><li>Press <b>Extract</b> button to start extraction.</li><br><br>6<li>Use <b>Browse</b> button to select the destination4folder fr" nocase ascii wide
      $var3 = {7E2024732572D181F9B8E4AE05150740623B7A4F5DA4CE3341E24F6D6D0F21F23356E55613C12597D7EB2884EB96D3773B491EAE2D1F472038AD96D1CEFA8ADBCDDE4E86C06855A15D69B2893C122471457D100000411C274A176E57AE62ECAA8922EFDDFBA2B6E4EFE117F2BD66338088B4373E2CB8BF91DEAC190864F4D44E6AFF350E6A}
      $var4 = {294424600F28F0660F6E5C241C660FFEF4660F6ED10F28C6660F6ECA660FEFC5660F62CA0F28E0660F72D00C660F72F414660FEFE0660F6E44242C660F62D80F28442460660F62D9660FFEDF660F6EF8660FFEDC660FEFC30F295C24500F28D8660F72D008660F72F318660FEFD80F28D3660F70DB39660FFED6}
      $var5 = {374DC673D0676DEA06A89B51F8F203C4A2E152A03A2310D7A9738544BAD912CF031887709B3ADC52E852B2E54EFB17072FA64DBEE1D7AB0A4FED628C7BECB9CE214066D4008315A1E675E3CCF2292F848100000000E4177764FBF5D3713D76A0E92F147D664CF4332EF1B8F38E0D0F1369944C73A80F26}
      $var6 = "lo haya hecho.\"\x0D\n\x0D\n; Dialog STARTDLG\x0D\n\x0D\n\x0D\n:DIALOG STARTDLG\x0D\n\x0D\nSIZE   " nocase ascii wide
      $winrar = "name=\"WinRAR SFX\"\x0D\n  type=\"win32\"/>\x0D\n<description>WinRAR SFX modu" nocase ascii
      $pdb = "Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" nocase ascii
      
   condition:
      $winrar and $pdb and 5 of ($var*) and filesize < 3MB 
}

rule signed_sys_with_vulnerablity {
    meta:
		description = "signed_sys_with_vulnerablity"
        date = "2023-07-21"
        author ="wonderkun"
        yarahub_reference_md5     = "3b25a34bb08f4759792c24b121109513"
        yarahub_uuid = "615591f5-2e81-4c01-8ebf-ab8aade6efcf"
        yarahub_license =  "CC0 1.0"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
        tlp = "WHITE"

    strings:
        $MmMapIoSpace = "MmMapIoSpace"
        $MapViewOfSection = "MapViewOfSection"
        $PhysicalMemory = "PhysicalMemory"
	condition:
		(pe.imports("ntoskrnl.exe") and pe.number_of_signatures > 0)
        and
        ($MmMapIoSpace or $MapViewOfSection or $PhysicalMemory)
}

rule sqlcmd_loader {
    meta:
        author = "@luc4m"
        date = "2023-03-26"
        hash_md5 = "6ffbbca108cfe838ca7138e381df210d"
        link = "https://medium.com/@lcam/updates-from-the-maas-new-threats-delivered-through-nullmixer-d45defc260d1"
        tlp = "WHITE"
	yarahub_uuid = "06196d3f-f414-4d87-9fe4-5dd40682f89f"
        yarahub_license =  "CC0 1.0"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
        yarahub_reference_md5= "6ffbbca108cfe838ca7138e381df210d" 
    strings:
        $trait_0 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 ec 04 00 00}
        $trait_1 = {85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 9f 04 00 00}
        $trait_2 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 7d 04 00 00}
        $trait_3 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 5b 04 00 00}
        $trait_4 = {6a 20 59 2b d9 03 f1 03 d1 3b d9 0f 83 5f fb ff ff}
        $trait_5 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 e3 03 00 00}
        $trait_6 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 c1 03 00 00}
        $trait_7 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 9f 03 00 00}
        $trait_8 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 4c 03 00 00}
        $trait_9 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 2a 03 00 00}

 $str_0 = /debug[0-9]{1,3}\.ps1/i wide
 $str_1 = "%s\\\\sysnative\\\\%s" wide
 $str_2 = "/c \\\"powershell " wide
 $str_3 = "%s/ab%d.exe" wide 
 $str_4 = "%s/ab%d.php" wide 

    condition:
        (5 of ($trait_*)) and (3 of ($str_*))
}

rule Sus_AnyDesk_Attempts_Feb2024 {
    meta:
        Description = "Detects files attempting to impersonate AnyDesk Windows Version"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Inspired by Florian Roth"
        Reference = "https://twitter.com/cyb3rops/status/1753440743480238459"
        Goodware_Hash = "55e4ce3fe726043070ecd7de5a74b2459ea8bed19ef2a36ce7884b2ab0863047"
        date = "2024-02-03"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "a21768190f3b9feae33aaef660cb7a83"
        yarahub_uuid = "b56ea799-6bae-4fd8-bc1a-362fc4c3aaf4"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    condition:
       pe.version_info["CompanyName"] contains  "AnyDesk"
       and pe.version_info["LegalCopyright"] != "(C) 2022 AnyDesk Software GmbH"
       and pe.pdb_path != "C:\\Users\\anyadmin\\Documents\\anydesk\\release\\app-32\\win_loader\\AnyDesk.pdb"
    
 }
 
rule SUS_UNC_InEmail
{
	meta:
		author = "Nicholas Dhaeyer - @DhaeyerWolf"
		date = "2023-05-15"
		description = "Looks for a suspicious UNC string in .eml files & .ole files"
		yarahub_uuid = "7df969ed-49f8-4c52-be25-6511d6dcc37f"
		yarahub_license = "CC BY-SA 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "1ac728095ebedb5d25bea43e69014bc4"
	  
	strings:
		$MAGIC_MSG = {D0 CF 11 E0 A1 B1 1A E1} // sadly the .msg message byte is the same as the one for other OLE files
		$MAGIC_EML = {52 65 63 65 69 76 65 64 3A} // Magic byte for .eml files: "Received:"
		$MAGIC_ICS = {42 45 47 49 4E 3A 56 43 41 4C 45 4E 44 41 52} // "BEGIN:VCALENDAR"
		
		$Appointment = "IPM.Appointment"
		
		$UNC = {00 5C 5C} 
	  
	condition:
		$UNC and ($MAGIC_MSG at 0 or $MAGIC_EML at 0 or $MAGIC_ICS at 0) and $Appointment
}

rule SUS_Unsigned_APPX_MSIX_Installer_Feb23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects suspicious, unsigned Microsoft Windows APPX/MSIX Installer Packages"
		reference = "https://twitter.com/SI_FalconTeam/status/1620500572481945600"
		date = "2023-02-01"
		tlp = "CLEAR"
		yarahub_reference_md5 = "69660f5abb08fc430cf756a44d19e039"
		yarahub_uuid = "3eaac733-4ab9-40e1-93fe-3dbed6d458e8"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		$s_manifest = "AppxManifest.xml"
		$s_block = "AppxBlockMap.xml"
		$s_peExt = ".exe"

		// we are not looking for signed packages
		$sig = "AppxSignature.p7x"

	condition:
		uint16be(0x0) == 0x504B
		and 2 of ($s*)
		and not $sig
}

rule SUS_Unsigned_APPX_MSIX_Manifest_Feb23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects suspicious Microsoft Windows APPX/MSIX Installer Manifests"
		reference = "https://twitter.com/SI_FalconTeam/status/1620500572481945600"
		date = "2023-02-01"
		tlp = "CLEAR"
		yarahub_reference_md5 = "69660f5abb08fc430cf756a44d19e039"
		yarahub_uuid = "06b5fba4-6b6d-41f8-9910-cce86eabbde4"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		$xlmns = "http://schemas.microsoft.com/appx/manifest/"
		
		// as documented here: https://learn.microsoft.com/en-us/windows/msix/package/unsigned-package
		$identity = "OID.2.25.311729368913984317654407730594956997722=1"
		
		$s_entrypoint = "EntryPoint=\"Windows.FullTrustApplication\""
		$s_capability = "runFullTrust"
		$s_peExt = ".exe"

	condition:
		uint32be(0x0) == 0x3C3F786D
		and $xlmns
		and $identity
		and 2 of ($s*)
}

rule SUSP_Doc_WordXMLRels_May22 {
   meta:
      description = "Detects a suspicious pattern in docx document.xml.rels file as seen in CVE-2022-30190 / Follina exploitation"
      author = "Tobias Michalski, Christian Burkard, Wojciech Cieslak"
      date = "2022-05-30"
      yarahub_reference_md5 = "5f15a9b76ad6ba5229cb427ad7c7a4f6"
      yarahub_uuid = "a9aad367-682e-440c-8732-dc414274b5c3"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
	  techniques = "File and Directory"
      modified = "2022-06-02"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      hash = "62f262d180a5a48f89be19369a8425bec596bc6a02ed23100424930791ae3df0"
      score = 70
   strings:
      $a1 = "<Relationships" ascii
      $a2 = "TargetMode=\"External\"" ascii

      $x1 = ".html!" ascii
      $x2 = ".htm!" ascii
   condition:
      filesize < 50KB
      and all of ($a*)
      and 1 of ($x*)
}

rule SUSP_HxD_Icon_Anomaly_May23_1 {
   meta:
      description = "Detects suspicious use of the the free hex editor HxD's icon in PE files that don't seem to be a legitimate version of HxD"
      author = "Florian Roth"
      reference = "https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios"

      date = "2023-05-30"
      yarahub_uuid = "b70e448c-b1c3-4edd-a109-e9bc5122a2ab"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_reference_md5 = "21e13f2cb269defeae5e1d09887d47bb"

   strings:
      /* part of the icon bitmap : we're not using resource hashes etc because YARA's string matching is much faster */
      $ac1 = { 99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D D0 99 98 09
               99 99 00 0D D0 99 98 09 99 99 00 0D D0 99 98 09
               99 99 00 0D D0 99 98 0F F9 99 00 0D D0 99 98 09
               9F 99 00 0D D0 99 98 09 FF 99 00 0D D0 99 98 09
               FF 99 00 0D D0 99 98 09 99 99 00 0D D0 99 98 0F
               F9 99 00 0D D0 99 98 09 99 99 00 0D 09 99 80 9F
               F9 99 99 00 09 99 80 99 F9 99 99 00 09 99 80 FF }
      $ac2 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF B9 DE
               FA 68 B8 F4 39 A2 F1 39 A2 F1 39 A2 F1 39 A2 F1
               39 A2 F1 39 A2 F1 68 B8 F4 B9 DE FA FF FF FF FF
               FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF }

      /* strings to expect in a HxD executable */
      $s1 = { 00 4D 00 61 00 EB 00 6C 00 20 00 48 00 F6 00 72 00 7A } /* Developer: Maael Hoerz */
      $s2 = "mh-nexus.de" ascii wide

      /* UPX marker */
      $upx1 = "UPX0" ascii fullword

      /* Keywords that are known to appear in malicious  samples */
      $xs1 = "terminator" ascii wide fullword // https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios
      $xs2 = "Terminator" ascii wide fullword // https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios
   condition:
      // HxD indicators
      uint16(0) == 0x5a4d 
      and 1 of ($ac*)
      // Anomalies
      and (
         not 1 of ($s*) // not one of the expected strings
         or filesize > 6930000 // no legitimate sample bigger than 6.6MB
         // all legitimate binaries have a known size and shouldn't be smaller than ...
         or ( pe.is_32bit() and filesize < 1540000 and not $upx1 )
         or ( pe.is_32bit() and filesize < 590000 and $upx1 )
         or ( pe.is_64bit() and filesize < 6670000 and not $upx1 )
         or ( pe.is_64bit() and filesize < 1300000 and $upx1 )
         // keywords expected in malicious samples
         or 1 of ($xs*)
      )
}

rule SUSP_NET_Large_Static_Array_In_Small_File_Jan24 {
    meta:
        description = "Detects large static arrays in small .NET files "
        author = "Jonathan Peters"
        date = "2024-01-11"
        reference = "https://github.com/Workingdaturah/Payload-Generator/tree/main"
        hash = "7d68bfaed20d4d7cf2516c2b110f460cf113f81872cd0cc531cbfa63a91caa36"
        score = 60
        yarahub_uuid = "4c809450-46e2-45a8-9fe2-1c14796ffffa"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1e324da03ebebfec519c030040943be0"
    strings:
        $op = "{ 5F 5F 53 74 61 74 69 63 41 72 72 61 79 49 6E 69 74 54 79 70 65 53 69 7A 65 3D [6-10] 00 }"
    condition:
        uint16 ( 0 ) == 0x5a4d and filesize < 300KB and #op == 1
}

rule SUSP_NET_Shellcode_Loader_Indicators_Jan24 {
    meta:
        description = "Detects indicators of shellcode loaders in .NET binaries"
        author = "Jonathan Peters"
        date = "2024-01-11"
        reference = "https://github.com/Workingdaturah/Payload-Generator/tree/main"
        hash = "c48752a5b07b58596564f13301276dd5b700bd648a04af2e27d3f78512a06408"
        score = 65
        yarahub_uuid = "eda4aae4-e33a-4a8c-9992-7979609bbde8"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "f03b6f7bff89bcba31d69706d3644350"
    strings:
        $sa1 = "VirtualProtect" ascii
        $sa2 = "VirtualAlloc" ascii
        $sa3 = "WriteProcessMemory" ascii
        $sa4 = "CreateRemoteThread" ascii
        $sa5 = "CreateThread" ascii
        $sa6 = "WaitForSingleObject" ascii
        $x = "__StaticArrayInitTypeSize=" ascii
    condition:
        uint16 ( 0 ) == 0x5a4d and 3 of ( $sa* ) and #x == 1
}

rule SUSP_ZIP_LNK_PhishAttachment {
    meta:
        description = "Detects suspicius tiny ZIP files with malicious lnk files"
        author = "ignacior"
        reference = "Internal Research"
        date = "2022-06-23"
        score = 50
        yarahub_uuid = "fbb7c8e8-55b6-4192-877b-3dbaad76e12e"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a457d941f930f29840dc8219796e35bd"
    strings:
        $sl1 = ".lnk"
    condition:
		uint16(0) == 0x4b50 and filesize < 2KB and $sl1 in (filesize-256..filesize)
}

rule Suspicious_PowerShellObjectCreation
{
	meta:
		date = "2025-02-13"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "7ee13c839f3af9ca9a4e8b692f7018fa"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "c88d3adb-5b6e-4b9a-b7fc-e15a409a55ad"
	strings:
		$base_1 = /\$ExecutionContext ?\| ?(Get-Member|gm)/ ascii nocase
		$optional_1 = "GetCommand" ascii nocase fullword
		$optional_2 = "Cmdlet" ascii nocase fullword
		$optional_3 = "PsObject" ascii nocase fullword
		$optional_4 = ")[6].Name)" ascii nocase fullword
	condition:
		$base_1 and
		2 of ($optional_*)
}

rule SVCReady_Packed
{
    meta:
        author                    = "Andre Gironda"
        date                      = "2022-06-08"
        description               = "packed SVCReady / win.svcready"
        hash                      = "326d50895323302d3abaa782d5c9e89e7ee70c3a4fbd5e49624b49027af30cc5"
        hash2                     = "76d69ec491c0711f6cc60fbafcabf095"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "andreg@gmail.com"
        yarahub_author_twitter    = "@AndreGironda"
        yarahub_license           = "CC0 1.0"
        yarahub_reference_md5     = "76d69ec491c0711f6cc60fbafcabf095"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "db8e2535-efef-4ada-a67f-919970546b1e"
   strings:
        $hex_1003b3e0 = { 52 75 6e 50 45 44 6c 6c 4e 61 74 69 76 65 3a 3a 46 69 6c 65 20 68 61 73 20 6e 6f 20 72 65 6c 6f 63 61 74 69 6f 6e }
        $hex_1003b424 = { 50 61 79 6c 6f 61 64 20 64 65 70 6c 6f 79 6d 65 6e 74 20 66 61 69 6c 65 64 2c 20 73 74 6f 70 70 69 6e 67 }
        $hex_1003c234 = { 4e 6f 74 20 73 75 70 70 6f 72 74 65 64 20 72 65 6c 6f 63 61 74 69 6f 6e 73 20 66 6f 72 6d 61 74 20 61 74 20 25 64 3a 20 25 64 0a 00 5b 2d 5d 20 }
        $hex_1003c2cc = { 49 6e 76 61 6c 69 64 20 61 64 64 72 65 73 73 20 6f 66 20 72 65 6c 6f 63 61 74 69 6f 6e 73 20 62 6c 6f 63 6b }
   condition:
        all of them
}

rule telegram_bot_api {
    meta:
        author = "rectifyq"
        yarahub_author_twitter = "@_rectifyq"
        date = "2024-09-07"
        description = "Detects file containing Telegram Bot API"
        yarahub_uuid = "58c9e4fe-d1e9-46ed-913c-dba943ac16d6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "9DA48D34DC999B4E05E0C6716A3B3B83"
    
    strings:
        $str1 = "api.telegram.org/bot" nocase
        $str2 = "api.telegram.org/bot" wide
        $str3 = "api.telegram.org/bot" xor
        
    condition:
        any of them
}  

rule TTP_Chinese_Dropper_March2024
{
  meta:
    author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
    description = "Detects Exetutables which are written in the Chinese Simplified Language and contain an embedded DLL within them"
    file_hash = "c0721d7038ea7b1ba4db1d013ce0c1ee96106ebd74ce2862faa6dc0b4a97700d"
    reference = "https://www.first.org/resources/papers/conference2010/cummings-slides.pdf"
    date = "2024-03-22"
    yarahub_author_twitter = "@RustyNoob619"
    yarahub_reference_md5 = "ee13e21a986f19d1259821fe5695a426"
    yarahub_uuid = "ad6415b7-81ff-4267-9da5-726e2b1f24e2"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    
  condition:
    pe.number_of_resources == 1
    and for any resource in pe.resources:
    (resource.language == 2052                             // Chinese Simplified and resource.
    and resource.type_string == "B\x00I\x00N\x00")        // Embedded DLL Payload 
    
}

rule TTP_Impersonating_Google_Updates_March2024 {
    meta:
        Description = "Detects Windows executables which are impersonating Google Update utilities"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "@ULTRAFRAUD shared a signed Async RAT sample disguised as Google Chrome"
        Reference = "https://twitter.com/ULTRAFRAUD/status/1771590513973395666"
        File_Hash = "3f4ab98919c1e1191dddcceac3d8962390b2ac9f08f13986b0965bdaa0cff202"
        date = "2024-03-24"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "59aeea49aac78a74854837f549a51e11"
        yarahub_uuid = "2991b087-4930-41c3-b272-bb5a3337fc5e"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        pe.version_info["LegalCopyright"] == "Copyright 2018 Google LLC"
        and pe.version_info["ProductName"] == "Google Update"
        and pe.number_of_signatures > 0 
        and not (for any sig in pe.signatures:
        (sig.thumbprint == "2673EA6CC23BEFFDA49AC715B121544098A1284C"       // 2021 to 2024 (most recent)
        or sig.thumbprint == "A3958AE522F3C54B878B20D7B0F63711E08666B2"    // 2019 to 2022 (Revoked)
        or sig.thumbprint == "CB7E84887F3C6015FE7EDFB4F8F36DF7DC10590E")) // 2018 to 2021 (Revoked)
 }
 
rule UmbrealStealerEXIFData {
    meta:
        description = "Detects UmbralStealer by obvious comment in EXIF Data"
        author = "adm1n_usa32"
        date = "2024-09-02"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_uuid = "9e454251-6212-4f36-8ebb-e64f694442e6"
        yarahub_license = "CC0 1.0"
        yarahub_reference_md5 = "83b81dda82a62350b52ee97a12d3163a"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $thishexstring = { 50 00 61 00 79 00 6C 00 6F 00 61 00 64 00 20 00 66 00 6F 00 72 00 20 00 55 00 6D 00 62 00 72 00 61 00 6C 00 20 00 53 00 74 00 65 00 61 00 6C 00 65 00 72 }
        $thistextstring = "Payload for Umbral Stealer"
    condition:
        $thishexstring or $thistextstring
}

rule UNKNOWN_News_Penguin_Feb2024 {
    meta:
        Description = "Detects an unknown File Type that was part of the tooling used by News Penguin to target orgs in Pakistan"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Is Now on VT! for notification of the malware sample"
        Reference = "https://blogs.blackberry.com/en/2023/02/newspenguin-a-previously-unknown-threat-actor-targets-pakistan-with-advanced-espionage-tool"
        Hash = "538bb2540aad0dcb512c6f0023607382456f9037d869b4bf00bcbdb18856b338"
        date = "2024-02-27"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "861b80a75ecfb083c46f6e52277b69a9"
        yarahub_uuid = "45cc6729-fe81-4055-ba74-40f5a17d4fae"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

strings:
    $penguin = "penguin"
    condition:
        #penguin > 100       
     
 }
 
rule vulnerablity_driver2_PhysicalMemory {
    meta:
		description = "vulnerablity_driver2_PhysicalMemory"
        date = "2023-07-21"
        author ="wonderkun"
        yarahub_reference_md5     = "3b25a34bb08f4759792c24b121109503"
        yarahub_uuid = "34512c64-fa1a-472b-89d7-ff36fafb943d"
        yarahub_license =  "CC0 1.0"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
        tlp = "WHITE"
    strings:
        $PhysicalMemory = "\\Device\\PhysicalMemory"
        $PhysicalMemory_Wide = "\\Device\\PhysicalMemory" wide
	condition:
        pe.is_64bit()
        and
        filesize > 3000KB
		and
		filesize < 10000KB
        and
        (pe.number_of_signatures >0)
        and
        (
            for all i in (0..pe.number_of_signatures - 1):
            (
            pe.signatures[i].valid_on(pe.timestamp)
            )
        )
        and
		(pe.imports("ntoskrnl.exe","ZwMapViewOfSection") or pe.imports("ntoskrnl.exe","NtMapViewOfSection"))
        and
        (($PhysicalMemory) or ($PhysicalMemory_Wide))
}

rule VxLang_Packer
{
  meta:
    author = "P4nd3m1cb0y"
    description = "Detects executables packed with VxLang"
    target_entity = "file"
    status = "RELEASED"
    date = "2023-11-14"
    yarahub_author_twitter = "@P4nd3m1cb0y"
    yarahub_reference_link = "https://github.com/vxlang/vxlang-page"
    yarahub_reference_md5 = "6c4d797d402ae5519c33f85e33d45fb6"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_license = "CC0 1.0"
    yarahub_uuid = "10fa6ea1-d58a-4cc6-89cc-fa1ca57a3050"
    hash = "7d9304eeb8f4c5823eecbedde65cc2877c809824c9203d16221c70eb591ee8ce"

  condition:
    uint16(0) == 0x5a4d and 
    for any i in (0 .. pe.number_of_sections) : (
        pe.sections[i].name contains ".vxil"
    )
}
