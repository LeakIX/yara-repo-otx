rule M_Hunting_Launcher_MISTCLOAK_1 {   
    meta:   
    author = "Mandiant"   
    strings:   
    $s1 = "CheckUsbService" ascii   
    $s2 = "new\\u2ec\\Release\\u2ec.pdb" ascii   
    $s3 = "autorun.inf\\Protection for Autorun" ascii   
    condition:   
    uint16(0) == 0x5a4d and   
    filesize < 200KB and   
    (2 of ($s*))   
   }