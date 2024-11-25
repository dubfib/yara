rule Win32_WinAPI_RegCreateKeyExW 
{
    meta:
        description = "Detects registry key creation from Win32 API function RegCreateKeyExW."
        author = "dubfib"
        date = "2024-11-25"

    strings:
        $pattern = { 52 65 67 43 72 65 61 74 65 4B 65 79 45 78 57 }

    condition:
        $pattern
}
