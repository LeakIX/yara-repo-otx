rule INDICATOR_EXE_Packed_Babel {   
       meta:   
           author = "ditekSHen"   
           description = "Detects executables packed with Babel"   
       strings:   
           $s1 = "BabelObfuscatorAttribute" fullword ascii   
       condition:   
           uint16(0) == 0x5a4d and 1 of them   
   }