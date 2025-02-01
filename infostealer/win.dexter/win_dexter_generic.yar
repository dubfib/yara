rule win_dexter_generic {
    meta:
        author = "dubfib"
        date = "2025-01-31"
        malpedia_family = "win.dexter"

        yarahub_uuid = "db18d542-40aa-455d-8905-ab955cca2270"
        yarahub_reference_md5 = "7d08306e5a837245c3f343c73535afef"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_license = "CC BY 4.0"
        yarahub_reference_link = "https://github.com/dubfib/yara"

    strings:
        $str0 = "Mozilla/4.0(compatible; MSIE 7.0b; Windows NT 6.0)" fullword ascii
        $str1 = "WindowsResilienceServiceMutex" fullword ascii
        $str2 = "UpdateMutex:" fullword ascii
        $str3 = "NoProcess" fullword ascii
        $str4 = "gateway.php" fullword ascii
        $str5 = "/portal1/gateway.php" fullword ascii
        $str6 = "images/logo/header.php" fullword ascii
        $str7 = "SecureDll.dll" fullword ascii
        $str8 = "wuauclt.exe" fullword ascii
        $str9 = "wmiprvse.exe" fullword ascii
        $str10 = "alg.exe" fullword ascii
        $str11 = "C:\\Program Files\\Internet Explorer\\iexplore.exe" fullword wide
        $str12 = ".DEFAULT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii
        $str13 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations" fullword ascii
        $str14 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0" fullword ascii

        $op0 = { c7 45 bc 40 34 00 00 c7 45 c0 }
        $opc1 = { 31 31 65 32 35 34 30 37 33 39 64 37 66 62 65 61 }
        $opc2 = { 37 31 38 36 33 34 33 61 38 30 63 36 66 61 33 32 }
        $opc3 = { 65 37 64 63 65 38 65 34 36 37 31 66 38 66 30 33 }
        $opc4 = { 8b 4d e8 8b 55 f4 2b 51 34 89 55 c8 8b 45 e8 8b }
        $opc5 = { 8b 55 64 52 ff 15 9c 81 00 00 e9 44 ff ff ff 83 } 
        $opc6 = { eb 34 8b 55 5c 0f b6 02 50 e8 ?? 0? 00 00 83 c4 }

    condition:
        uint16(0) == 0x5A4D and 
        5 of ($str*) and
        2 of ($op*)
}