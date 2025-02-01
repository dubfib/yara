import "pe"

rule win_lumma_2eabe9054cad5152567f0699947a2c5b {
    meta:
        author = "dubfib"
        date = "2025-01-31"
        malpedia_family = "win.lumma"

        yarahub_uuid = "5f897f77-9e52-4585-a91c-c70fec7f91ed"
        yarahub_reference_md5 = "26b5af1cfc3efc73b6d9be8f11412a9b"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_license = "CC BY 4.0"
        yarahub_reference_link = "https://github.com/dubfib/yara"

    strings:
        $asm0 = {20696e} /* 1068: and byte ptr [ecx + 0x6e], ch */
        $asm1 = {005045} /* 1077: add byte ptr [eax + 0x45], dl */
        $asm2 = {64652e2400} /* 1072: and al, 0 */
        $asm3 = {b8014ccd21} /* 1049: mov eax, 0x21cd4c01 */
        $asm4 = {206d6f} /* 106f: and byte ptr [ebp + 0x6f], ch */
        $asm5 = {ba0e00b409} /* 1042: mov edx, 0x9b4000e */
        $asm6 = {007800} /* 103b: add byte ptr [eax], bh */
        $asm7 = {677261} /* 1056: jb 0x10ba */
        $asm8 = {206361} /* 105a: and byte ptr [ebx + 0x61], ah */
        $asm9 = {626520} /* 1062: bound esp, qword ptr [ebp + 0x20] */
        $asm10 = {6869732070} /* 104f: push 0x70207369 */
        $asm11 = {20444f53} /* 106b: and byte ptr [edi + ecx*2 + 0x53], al */

    condition:
        uint16(0) == 0x5A4D and 
        pe.imphash() == "2eabe9054cad5152567f0699947a2c5b" and 
        all of them
}
