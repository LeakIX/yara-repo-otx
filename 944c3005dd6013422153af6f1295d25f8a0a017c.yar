rule M_Hunting_Launcher_BLUEHAZE_1 {   
    meta:   
    author = "Mandiant"   
    strings:   
    $s1 = "Libraries\\CNNUDTV" ascii   
    $s2 = "closed.theworkpc.com" ascii   
    $s3 = "cmd.exe /C wuwebv.exe -t -e" ascii   
    condition:   
    uint16(0) == 0x5a4d and   
    filesize < 500KB and   
    (2 of ($s*))   
   }