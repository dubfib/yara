rule js_formbook {
    meta:
        author = "dubfib"
        date = "2025-02-08"
        
        yarahub_uuid = "d28e72fa-2371-48ec-abe2-d135c02e54cf"
        yarahub_reference_md5 = "250e3366ed43c2f8738de0263a9bffcd"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_license = "CC BY 4.0"
        yarahub_reference_link = "https://github.com/dubfib/yara"

    strings:
        $str0 = "Status" ascii
        $str1 = "PowerShell\\x20-NoProfile\\x20-ExecutionPolicy\\x20RemoteSigned\\x20-File\\x20" ascii
        $str2 = "Scripting.FileSystemObject" ascii
        $str3 = "MSXML2.XMLHTTP" ascii
        $str4 = "CreateObject" ascii
        $str5 = "CreateTextFile" ascii
        $str6 = "FolderExists" ascii
        $str7 = "CreateFolder" ascii
        $str8 = "Exiting\\x20script\\x20due\\x20to\\x20download\\x20failure." ascii
        $str9 = "HTTP\\x20request\\x20failed\\x20with\\x20status\\x20code:\\x20" ascii
        $str10 = "C:\\x5cTemp" ascii
        $str11 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=" ascii

    condition:
        filesize < 15KB and 6 of ($str*)
}
