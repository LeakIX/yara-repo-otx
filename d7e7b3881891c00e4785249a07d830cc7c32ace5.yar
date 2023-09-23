import "pe"
rule M_Hunting_Win_FONELAUNCH   
   {   
    meta:   
    author = "Mandiant"   
    description = "Hunting rule looking for suspicious version information metadata observed in FONELAUNCH samples"   
    md5 = "35238d2a4626e7a1b89b13042f9390e9"   
    strings:   
    $m1 = { 49 00 6E 00 74 00 65 00 72 00 6E 00 61 00 6C 00 4E 00 61 00 6D 00 65 00 00 00 70 00 6F 00 77 00 65 00 72 00 73 00 68 00 65 00 6C 00 6C 00 2E 00 64 00 6C 00 6C 00 }   
    $m2 = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 6F 00 77 00 65 00 72 00 73 00 68 00 65 00 6C 00 6C 00 2E 00 64 00 6C 00 6C 00 }   
    condition:   
    filesize < 15MB and uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and (pe.version_info["OriginalFilename"] == "powershell.dll" or pe.version_info["InternalName"] ==   
    "powershell.dll" or any of ($m*)) }