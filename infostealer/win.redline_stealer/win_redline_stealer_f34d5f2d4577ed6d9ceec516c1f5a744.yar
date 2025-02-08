import "pe"

rule win_redline_stealer_f34d5f2d4577ed6d9ceec516c1f5a744 {
    meta:
        author = "dubfib"
        date = "2025-02-08"
        malpedia_family = "win.redline_stealer"

        yarahub_uuid = "5f04574d-e2cf-4cbb-b69b-c664cda2b09d"
        yarahub_reference_md5 = "65b74f187c506cf5c1fafde03e60e7df"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_license = "CC BY 4.0"
        yarahub_reference_link = "https://github.com/dubfib/yara"

    strings:
        $opc0 = {013400000200b50026db000e}
        $opc1 = {020005002c4d00008834010003000200}
        $opc2 = {0600c709c5130600340ac5130600e208}
        $opc3 = {080000110072344000701a7275000070}
        $opc4 = {110000110020ffffff7f0a160b2b1a00}
        $opc5 = {14fe0627000006733400000a80190000}
        $opc6 = {14fe0666000006739e00000a80340000}
        $opc7 = {1b300200b301000034000011000314fe}
        $opc8 = {1e000011739d00000a0a037e34000004}
        $opc9 = {1f34734800000a6f4900000a00026f2e}
        $opc10 = {2901002433653263343536392d636231}
        $opc11 = {2e0500003405000003}
        $opc12 = {2e735100000680340000042a2202289e}
        $opc13 = {3900000634f00000e88009}
        $opc14 = {46460003010000016e02d03400001b28}
        $opc15 = {6f6f00000a00027b34000004724b0300}
        $opc16 = {6fba00000a2521ffffff7f}
        $opc17 = {73220000060c087b34000004027b2200}
        $opc18 = {734301000a2520ffffff7f6f4401000a}
        $opc19 = {75fe29794134092bdd9a0c3644f14442}
        $opc20 = {8100340d0b0512006926}
        $opc21 = {86003418060001005821}
        $opc22 = {8618e01506002e00343b}
        $opc23 = {9100340317052c001b3a}
        $opc24 = {9100e71932053400d83e}
        $opc25 = {ff135900ff8c02ffff2b0713ffffff25}
        $opc26 = {ff367b04fffffff6ff000015ff1707b1}
        $opc27 = {076f5a00000a3a2bffffffde1507752c}
        $opc28 = {1204283300000a130500110573340000}
        $opc29 = {30003100320033003400360038003800}

    condition:
        uint16(0) == 0x5a4d and
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and
        3 of ($opc*)
}