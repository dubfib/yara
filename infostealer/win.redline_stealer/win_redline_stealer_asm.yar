rule win_redline_stealer_asm {
    meta:
        author = "dubfib"
        date = "2025-02-22"
        malpedia_family = "win.redline_stealer"

        yarahub_uuid = "bbcc957c-a1ad-483e-873e-4b77e815f072"
        yarahub_reference_md5 = "e24baa016c4432a863aa8b097412f527"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_license = "CC BY 4.0"
        yarahub_reference_link = "https://github.com/dubfib/yara"

    strings:
        $asm0 = {
            00 E0 /* add al, ah */
            92 /* xchg edx, eax*/
            01 00 /* add dword ptr ds:[eax], eax */
            4B /* dec ebx */
        }
        
    condition:
        uint16(0) == 0x5a4d and
        any of ($asm*)
}
