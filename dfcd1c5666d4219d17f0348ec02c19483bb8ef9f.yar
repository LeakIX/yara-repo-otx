rule M_Hunting_Dropper_DARKDEW_1 {   
    meta:   
    author = "Mandiant"   
    strings:   
    $s1 = "do inroot" ascii   
    $s2 = "disk_watch" ascii   
    $s5 = "G:\\project\\APT\\" ascii   
    $s3 = "c:\\programdata\\udisk" ascii   
    $s4 = "new\\shellcode\\Release\\shellcode.pdb" ascii   
    condition:   
    filesize < 500KB and   
    (2 of ($s*))   
   }