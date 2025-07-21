import "pe"
import "dotnet"

rule RansomPyShield_Antiransomware {

    meta:
        author = "XiAnzheng"
        source_url = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware"
        description = "Check for Suspicious String and Import combination that Ransomware mostly abuse(can create FP)"
        date = "2024-11-07"
        updated = "2024-11-20"
        yarahub_license = "CC0 1.0"
        yarahub_uuid = "3295ce35-cb35-4203-bb37-7503ddf111c5"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "16f76e17d64f5ee805031ddf9f862f59"

    strings:
        // Detect DotNet Namespace Cryptography Function
        $dotnet1 = "AES_Encrypt" wide ascii
        $dotnet2 = "RijndaelManaged"  wide ascii
        $dotnet3 = "SymmetricAlgorithm" wide ascii
        $dotnet4 = "PaddingMode" wide ascii
        $dotnet5 = "Rfc2898DeriveBytes" wide ascii
        $dotnet6 = "DeriveBytes" wide ascii
        $dotnet7 = "CipherMode" wide ascii
        $dotnet8 = "CryptoStream" wide ascii
        $dotnet9 = "CryptoStreamMode" wide ascii
        $dotnet10 = "RSACryptoServiceProvider" wide ascii
        $dotnet11 = "RSAEncryptionPadding" wide ascii
        $dotnet12 = "AsymmetricAlgorithm" wide ascii

    condition:
        any of them
        
        // Encryption Function Call (Can create FP)
		or (pe.imports("advapi32.dll", "CryptImportKey")) 
        or (pe.imports("advapi32.dll", "CryptEncrypt"))
        or (pe.imports("advapi32.dll", "CryptDecrypt"))
		or (pe.imports("advapi32.dll", "CryptGenKey"))
        or (pe.imports("advapi32.dll", "CryptGenRandom"))
        or (pe.imports("advapi32.dll", "CryptCreateHash")) 
        or (pe.imports("advapi32.dll", "CryptHashData"))
        or (pe.imports("advapi32.dll", "CryptDeriveKey"))
        or (pe.imports("advapi32.dll", "CryptDestroyHash"))
        
        // Using BCrypt , NCrypt , Crypt32 (Can create FP)
		or pe.imports("bcrypt.dll") 
		or pe.imports("ncrypt.dll")	
		or pe.imports("crypt32.dll")

        // Detect Dotnet Ransomware (Can Create FP)
        or (any of them and (
            pe.imports("mscoree.dll") or dotnet.is_dotnet
            ) 
        )
}