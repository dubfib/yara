rule Win32_Infostealer_Dexter
{
    meta:
        description = "Detects Dexter Infostealer for Windows"
        author = "dubfib"
        date = "2024-11-27"
        yarahub_uuid = "a8d585fb-52a0-4e71-9870-eb55495d08e3"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "7d419cd096fec8bcf945e00e70a9bc41"

    strings:
        //Mozilla/4.0(compatible; MSIE 7.0b; Windows NT 6.0)
        $useragent = {
            4D 6F 7A 69 6C 6C 61 2F 34 2E 30 28 63 6F 6D 70
            61 74 69 62 6C 65 3B 20 4D 53 49 45 20 37 2E 30
            62 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E
            30 29
        }

        //gateway.php
        $gateway = { 67 61 74 65 77 61 79 2E 70 68 70 }

        //UpdateMutex
        $updatemutex = { 55 70 64 61 74 65 4D 75 74 65 78 3A }

        //Software or SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        $registry = {
            53 (4F | 6F) (46 | 66) (54 | 74) (57 | 77) (41 | 61) (52 | 72) (45 | 65) 5C 4D 69 63
            72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 5C 43
            75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 52 75
            6E
        }

    condition:
        //if file is pe and matches all strings
        uint16(0) == 0x5A4D and all of them
}