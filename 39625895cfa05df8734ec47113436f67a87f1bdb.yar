import "pe"
rule INDICATOR_EXE_Packed_UPolyX {   
       meta:   
           author = "ditekSHen"   
           description = "Detects executables packed with UPolyX"   
       strings:   
           $s1 = { 81 fd 00 fb ff ff 83 d1 ?? 8d 14 2f 83 fd fc 76 ?? 8a 02 42 88 07 47 49 75 }   
           $s2 = { e2 ?? ff ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }   
           $s3 = { 55 8b ec ?? 00 bd 46 00 8b ?? b9 ?? 00 00 00 80 ?? ?? 51 }   
           $s4 = { bb ?? ?? ?? ?? 83 ec 04 89 1c 24 ?? b9 ?? 00 00 00 80 33 }   
           $s5 = { e8 00 00 00 00 59 83 c1 07 51 c3 c3 }   
           $s6 = { 83 ec 04 89 ?? 24 59 ?? ?? 00 00 00 }   
       condition:   
           uint16(0) == 0x5a4d and 1 of them and   
           for any i in (0 .. pe.number_of_sections) : (   
               (   
                   pe.sections[i].name contains "UPX"   
               )   
           )   
   }