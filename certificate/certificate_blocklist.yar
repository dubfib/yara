import "pe"

rule certificate_blocklist_2595bcf2c3ae82b63703af36e1256a9a 
{
    meta:
        description = "Certificate misused for malicious code signing"
        author = "dubfib"
        date = "2024-12-25"
        sharing = "TLP:WHITE"
        license = "CC BY 4.0"
 
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nguy" and
            pe.signatures[i].issuer contains "SSL.com Code Signing Intermediate CA ECC R2" and
            pe.signatures[i].serial == "25:95:bc:f2:c3:ae:82:b6:37:03:af:36:e1:25:6a:9a" and
            pe.signatures[i].thumbprint == "d8fa17e7682967e78a3110a806d0494f045b163e" and
            pe.signatures[i].algorithm == "ecdsa-with-SHA384" and
            pe.signatures[i].not_after >= 1766510580
        )
}
 
rule certificate_blocklist_5ab8891e9a0a7996494081ed71f471ee
{
    meta:
        description = "Certificate misused for malicious code signing"
        author = "dubfib"
        date = "2024-12-25"
        sharing = "TLP:WHITE"
        license = "CC BY 4.0"
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lenovo HelpCentr" and
            pe.signatures[i].issuer contains "Lenovo HelpCentr" and
            pe.signatures[i].serial == "5a:b8:89:1e:9a:0a:79:96:49:40:81:ed:71:f4:71:ee" and
            pe.signatures[i].thumbprint == "5f939042543bc5b5b26ee42d3b2f7cc31c8f6b07" and
            pe.signatures[i].algorithm == "sha1WithRSAEncryption" and
            pe.signatures[i].not_after >= 2050584840
        ) 
}
 
rule certificate_blocklist_417b3a9c446891f15b00caeb70d95cb6
{
    meta:
        description = "Certificate misused for malicious code signing"
        author = "dubfib"
        date = "2024-12-25"
        sharing = "TLP:WHITE"
        license = "CC BY 4.0"
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Quanzhou Chunsheng Technology Co., Ltd." and
            pe.signatures[i].issuer contains "Certum Extended Validation Code Signing 2021 CA" and
            pe.signatures[i].serial == "41:7b:3a:9c:44:68:91:f1:5b:00:ca:eb:70:d9:5c:b6" and
            pe.signatures[i].thumbprint == "56856ff8ade9dd49fd006c6dcf413a4c103dd079" and
            pe.signatures[i].algorithm == "sha256WithRSAEncryption" and
            pe.signatures[i].not_after >= 1753508880
        ) 
}
 
rule certificate_blocklist_3b1955cfeaa2c9c392292e00287d4a6c
{
    meta:
        description = "Certificate misused for malicious code signing"
        author = "dubfib"
        date = "2024-12-25"
        sharing = "TLP:WHITE"
        license = "CC BY 4.0"
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MECHA MANGA - FZCO" and
            pe.signatures[i].issuer contains "Sectigo Public Code Signing CA R36" and
            pe.signatures[i].serial == "3b:19:55:cf:ea:a2:c9:c3:92:29:2e:00:28:7d:4a:6c" and
            pe.signatures[i].thumbprint == "1f3cce31883c9ef47711a1ee96294e479ce69cfb" and
            pe.signatures[i].algorithm == "sha384WithRSAEncryption" and
            pe.signatures[i].not_after >= 1742943540
        ) 
}
 
rule certificate_blocklist_5e8f74e19a3ab88e76aa9aed28ee1ac63d35f58f
{
    meta:
        description = "Certificate misused for malicious code signing"
        author = "dubfib"
        date = "2024-12-25"
        sharing = "TLP:WHITE"
        license = "CC BY 4.0"
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Skovsneglen" and
            pe.signatures[i].issuer contains "Skovsneglen" and
            pe.signatures[i].serial == "5e:8f:74:e1:9a:3a:b8:8e:76:aa:9a:ed:28:ee:1a:c6:3d:35:f5:8f" and
            pe.signatures[i].thumbprint == "64c8e8be1ab377c991ba18b0d7d159956383e7c9" and
            pe.signatures[i].algorithm == "sha256WithRSAEncryption" and
            pe.signatures[i].not_after >= 1752377700
        ) 
}
 
rule certificate_blocklist_5608cab7e2ce34d53abcbb73
{
    meta:
        description = "Certificate misused for malicious code signing"
        author = "dubfib"
        date = "2024-12-25"
        sharing = "TLP:WHITE"
        license = "CC BY 4.0"
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ataleo GmbH" and
            pe.signatures[i].issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
            pe.signatures[i].serial == "56:08:ca:b7:e2:ce:34:d5:3a:bc:bb:73" and
            pe.signatures[i].thumbprint == "be7156bd07dd7f72521fae4a3d6f46c48dd2ce9e" and
            pe.signatures[i].algorithm == "sha256WithRSAEncryption" and
            pe.signatures[i].not_after >= 1797861540
        ) 
}
 
rule certificate_blocklist_671946870b21e63194a831ccb854a5fecef0ae3d
{
    meta:
        description = "Certificate misused for malicious code signing"
        author = "dubfib"
        date = "2024-12-25"
        sharing = "TLP:WHITE"
        license = "CC BY 4.0"
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cowhages" and
            pe.signatures[i].issuer contains "Cowhages" and
            pe.signatures[i].serial == "67:19:46:87:0b:21:e6:31:94:a8:31:cc:b8:54:a5:fe:ce:f0:ae:3d" and
            pe.signatures[i].thumbprint == "d11d7ed69f9232a86043c87d93145a21ae570114" and
            pe.signatures[i].algorithm == "sha256WithRSAEncryption" and
            pe.signatures[i].not_after >= 1761805920
        ) 
}
 
rule certificate_blocklist_0ddaf2fe51f3b2e94cbb695a4a5174fc
{
    meta:
        description = "Certificate misused for malicious code signing"
        author = "dubfib"
        date = "2024-12-25"
        sharing = "TLP:WHITE"
        license = "CC BY 4.0"
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tencent Technology (Shenzhen) Company Limited" and
            pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
            pe.signatures[i].serial == "0d:da:f2:fe:51:f3:b2:e9:4c:bb:69:5a:4a:51:74:fc" and
            pe.signatures[i].thumbprint == "617c4edb4f205fca0e5c07b9c52aa8d695fd122c" and
            pe.signatures[i].algorithm == "sha256WithRSAEncryption" and
            pe.signatures[i].not_after >= 1760741940
        ) 
}
 
rule certificate_blocklist_664fb5cf8909a1b940e83a4c77110e2d
{
    meta:
        description = "Certificate misused for malicious code signing"
        author = "dubfib"
        date = "2024-12-25"
        sharing = "TLP:WHITE"
        license = "CC BY 4.0"
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lenovo PRO Korea" and
            pe.signatures[i].issuer contains "Lenovo PRO Korea" and
            pe.signatures[i].serial == "66:4f:b5:cf:89:09:a1:b9:40:e8:3a:4c:77:11:0e:2d" and
            pe.signatures[i].thumbprint == "97ad13fc6a85103eb71b24f9c01b86cd7ba29f3a" and
            pe.signatures[i].algorithm == "sha1WithRSAEncryption" and
            pe.signatures[i].not_after >= 2050246620
        ) 
}
 
rule certificate_blocklist_0b9360051bccf66642998998d5ba97ce
{
    meta:
        description = "Certificate misused for malicious code signing"
        author = "dubfib"
        date = "2024-12-25"
        sharing = "TLP:WHITE"
        license = "CC BY 4.0"
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Connectwise, LLC" and
            pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
            pe.signatures[i].serial == "0b:93:60:05:1b:cc:f6:66:42:99:89:98:d5:ba:97:ce" and
            pe.signatures[i].thumbprint == "4c2272fba7a7380f55e2a424e9e624aee1c14579" and
            pe.signatures[i].algorithm == "sha256WithRSAEncryption" and
            pe.signatures[i].not_after >= 1755298740
        ) 
}
 
rule certificate_blocklist_4ee95aa19aad660af5fd37ca
{
    meta:
        description = "Certificate misused for malicious code signing"
        author = "dubfib"
        date = "2024-12-25"
        sharing = "TLP:WHITE"
        license = "CC BY 4.0"
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            //pe.signatures[i].subject contains "广西月海映画网络科技有限公司" and
            pe.signatures[i].issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
            pe.signatures[i].serial == "4e:e9:5a:a1:9a:ad:66:0a:f5:fd:37:ca" and
            pe.signatures[i].thumbprint == "65d32737a3bd8bf76582684064db2847d049f393" and
            pe.signatures[i].algorithm == "sha256WithRSAEncryption" and
            pe.signatures[i].not_after >= 1736995320
        ) 
}
 
rule certificate_blocklist_785bffb46042ae6fa592ca35
{
    meta:
        description = "Certificate misused for malicious code signing"
        author = "dubfib"
        date = "2024-12-25"
        sharing = "TLP:WHITE"
        license = "CC BY 4.0"
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bits Department LLC" and
            pe.signatures[i].issuer contains "GlobalSign GCC R45 CodeSigning CA 2020" and
            pe.signatures[i].serial == "78:5b:ff:b4:60:42:ae:6f:a5:92:ca:35" and
            pe.signatures[i].thumbprint == "11694e93100a6f1bc6479e1a2b7e76b4e64f3ad3" and
            pe.signatures[i].algorithm == "sha256WithRSAEncryption" and
            pe.signatures[i].not_after >= 1791222180
        ) 
}
