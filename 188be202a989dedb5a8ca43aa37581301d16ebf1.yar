rule INDICATOR_EXE_Packed_KoiVM {   
       meta:   
           author = "ditekSHen"   
           description = "Detects executables packed with or use KoiVM"   
       strings:   
           $s1 = "KoiVM v" ascii wide   
           $s2 = "DarksVM " ascii wide   
           $s3 = "Koi.NG" ascii wide   
       condition:   
           uint16(0) == 0x5a4d and 1 of them   
   }