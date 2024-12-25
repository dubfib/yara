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
            pe.signatures[i].not_after >= 2050584840
        ) 
}
