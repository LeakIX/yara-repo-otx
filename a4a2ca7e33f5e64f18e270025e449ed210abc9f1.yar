rule AUI001_InfoStealer_85233_98005 {   
   meta:   
   author = "Cluster25"   
   description = "Detects final-stage payload of AUI001 InfoStealer RAT"   
   tlp = "white"   
   score = 100   
   strings:   
   $r1 = "Pool" fullword ascii   
   $r2 = "Soccer" fullword ascii   
   $r3 = "Street" fullword ascii   
   $r4 = "Football" fullword ascii   
   $g1 = "GZipStream" fullword ascii   
   $f1 = "get_Module" fullword ascii   
   $f2 = "Reverse" fullword ascii   
   $f3 = "BlockCopy" fullword ascii   
   $f4 = "ReadByte" fullword ascii   
   $s1 = "{11111-22222-10009-11112}" fullword wide   
   $s2 = "{11111-22222-50001-00000}" fullword wide   
   $s3 = { 4c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00   
           00 0b 46 00 69 00 6e 00 64 00 20 00 00 13 52 00   
           65 00 73 00 6f 00 75 00 72 00 63 00 65 00 41 00   
           00 11 56 00 69 00 72 00 74 00 75 00 61 00 6c 00   
           20 00 00 0b 41 00 6c 00 6c 00 6f 00 63 00 00 0d   
           57 00 72 00 69 00 74 00 65 00 20 00 00 11 50 00   
           72 00 6f 00 63 00 65 00 73 00 73 00 20 00 00 0d   
           4d 00 65 00 6d 00 6f 00 72 00 79 00 00 0f 50 00   
           72 00 6f 00 74 00 65 00 63 00 74 00 00 0b 4f 00   
           70 00 65 00 6e 00 20 00 00 0f 50 00 72 00 6f 00   
           63 00 65 00 73 00 73 00 00 0d 43 00 6c 00 6f 00   
           73 00 65 00 20 00 00 0d 48 00 61 00 6e 00 64 00   
           6c 00 65 00 00 0f 6b 00 65 00 72 00 6e 00 65 00   
           6c 00 20 00 00 0d 33 00 32 00 2e 00 64 00 6c 00   
           6c }   
   condition:   
   uint16(0) == 0x5a4d and    
   $g1 and    
   (all of ($r*) or    
   (all of ($f*) and    
   2 of ($s*) ))   
   }