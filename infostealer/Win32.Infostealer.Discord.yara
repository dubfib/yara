rule Win32_Infostealer_Discord
{
    meta:
        description = "Detects an Infostealer targeting or using Discord (WIP)"
        author = "dubfib"
        date = "2024-11-25"
        //yarahub_uuid = ""
        //yarahub_license = "CC BY 4.0"
        //yarahub_rule_matching_tlp = "TLP:WHITE"
        //yarahub_rule_sharing_tlp = "TLP:WHITE"
        //yarahub_reference_md5 = ""
htehtwehwre
    strings:
        $path = "discord\\Local Storage\\leveldb" nocase

        $ldb = { 
            2E 6C 64 62
            [0-32]       
            64 69 73 63 6F 72 64
        }

        $log = /discord.*\.log|\.log.*discord|leveldb.*\.log/i

        $webhook = /https:\/\/(canary\.|ptb\.)?discord(app)?\.com\/api\/webhooks\/[0-9]{17,19}/i
        $token = /[\w-]{26}\.[\w-]{6}\.[\w-]{38}/i

    condition:
        any of ($path, $ldb, $log) or
        ($webhook and $token)
}
