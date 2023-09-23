rule CISA_10400779_07 : webshell    
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10400779"   
      
   				 Date = "2022-08-29"   
      
   				 Last_Modified = "20220908_1400"   
      
   				 Actor = "n/a"   
      
   				 Category = "Webshell"   
      
   				 Family = "n/a"   
      
   				 Description = "Detects JSP Webshell samples"   
      
   				 MD5 = "6f1c2dd27e28a52eb09cdd2bc828386d"   
      
   				 SHA256 = "6dee4a1d4ac6b969b1f817e36cb5d36c5de84aa8fe512f3b6e7de80a2310caea"   
      
   				strings:   
      
   				 $s0 = { 78 3D 55 52 4C 44 65 63 6F 64 65 72 }   
      
   				 $s1 = { 53 74 72 69 6E 67 20 6F 2C 6C 2C 64 }   
      
   				 $s2 = { 72 65 71 75 65 73 74 2E 67 65 74 49 6E 70 75 74 53 74 72 65 61 6D }   
      
   				 $s3 = { 69 6E 64 65 78 4F 66 28 22 63 3D 22 29 }   
      
   				 $s4 = { 2E 65 78 65 63 28 67 29 }   
      
   				 $s5 = { 6F 75 74 2E 70 72 69 6E 74 }   
      
   				 $s6 = { 70 61 72 73 65 42 61 73 65 36 34 42 69 6E 61 72 79 }   
      
   				 $s7 = { 46 69 6C 65 2E 73 65 70 61 72 61 74 6F 72 }   
      
   				 $s8 = { 6F 3D 22 55 70 6C 6F 61 64 65 64 }   
      
   				 $s9 = { 6F 75 74 2E 70 72 69 6E 74 28 65 29 }   
      
   				condition:   
      
   				 filesize < 10KB and all of them   
      
   				}