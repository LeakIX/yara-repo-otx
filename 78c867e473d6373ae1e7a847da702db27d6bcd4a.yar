rule Zeppelin_29 {   
      meta:   
         description = "Zeppelin - from files 8d44fdbedd0ec9ae59fad78bdb12d15d6903470eb1046b45c227193b233adda6, 42770c6589ccf83a6712aca6f9d990a0c24b664887d5f5dead5d5f123c7b7ef9"   
         author = "yarGen Rule Generator"   
         reference = "https://github.com/Neo23x0/yarGen"   
         date = "2022-08-08"   
         hash1 = "8d44fdbedd0ec9ae59fad78bdb12d15d6903470eb1046b45c227193b233adda6"   
         hash2 = "42770c6589ccf83a6712aca6f9d990a0c24b664887d5f5dead5d5f123c7b7ef9"   
      strings:   
         $s1 = "comdlg32.dll" fullword ascii   
         $s2 = "comctl32.dll" fullword ascii   
         $s3 = "winspool.drv" fullword ascii   
         $s4 = "FindTextA" fullword ascii   
         $s5 = "AlphaBlend" fullword ascii   
         $s6 = "StartDocPrinterW" fullword ascii   
         $s7 = "DllRegisterServer" fullword ascii   
         $s8 = "H_^ZYX" fullword ascii   
         $s9 = "G_^ZYX" fullword ascii   
      condition:   
         ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )   
         ) or ( all of them )   
   }