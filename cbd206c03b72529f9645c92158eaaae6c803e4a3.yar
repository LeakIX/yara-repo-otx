import "pe"
rule INDICATOR_EXE_Packed_ASPack {   
       meta:   
           author = "ditekSHen"   
           description = "Detects executables packed with ASPack"   
           snort2_sid = "930007-930009"   
           snort3_sid = "930002"   
       //strings:   
       //    $s1 = { 00 00 ?? 2E 61 73 70 61 63 6B 00 00 }   
       condition:   
           uint16(0) == 0x5a4d and //all of them or   
           for any i in (0 .. pe.number_of_sections) : (   
               (   
                   pe.sections[i].name == ".aspack"   
               )   
           )   
   }