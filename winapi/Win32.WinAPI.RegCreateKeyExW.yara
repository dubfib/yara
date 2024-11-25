rule Win32_WinAPI_RegCreateKeyExW 
{
    meta:
        description = "Detects registry key creation from Win32 API function RegCreateKeyExW."
        author = "dubfib"
        date = "2024-11-25"
        yarahub_uuid = "56359ae0-c915-467f-8b48-9410086f274d"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "93937d77-2637-4c9d-a8c6-a9973cebfd16"

    strings:
        $pattern = { 52 65 67 43 72 65 61 74 65 4B 65 79 45 78 57 }

    condition:
        $pattern
}