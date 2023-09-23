rule CISA_10400779_05 : utility webshell ZIMBRA   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10400779"   
      
   				 Date = "2022-08-29"   
      
   				 Last_Modified = "20220908_1400"   
      
   				 Actor = "n/a"   
      
   				 Category = "Utility Webshell"   
      
   				 Family = "ZIMBRA"   
      
   				 Description = "Detects malicious JSP webshell samples"   
      
   				 MD5 = "55e51e8ceda717813a5223a8c99a8830"   
      
   				 SHA256 = "9d2a842e7a39358adc68311dcc0bc550ba375eae7513a3d4de326e948d09c245"   
      
   				strings:   
      
   				 $s0 = { 2f 6f 70 74 2f 7a 69 6d 62 72 61 2f 6a 65 74 74 79 2f 77 65 62 61 70 70 73 2f 7a 69 6d 62 72 61 41 64 6d 69 6e 2f 70 75 62 6c 69 63 2f 74 65 73 74 2e 73 68 }   
      
   				 $s1 = { 2E 65 78 65 63 28 }   
      
   				 $s2 = { 5A 69 70 4F 75 74 70 75 74 53 74 72 65 61 6D }   
      
   				 $s3 = { 67 65 74 50 61 72 61 6D 65 74 65 72 }   
      
   				 $s4 = { 22 61 63 74 69 6F 6E 22 }   
      
   				 $s5 = { 22 65 78 65 63 22 2E }   
      
   				 $s6 = { 70 72 69 6E 74 6C 6E 28 65 78 65 63 }   
      
   				 $s7 = { 22 64 6F 77 6E 22 2E }   
      
   				 $s8 = { 43 6F 6E 74 65 6E 74 2D 44 69 73 70 6F 73 69 74 69 6F 6E }   
      
   				 $s9 = { 61 74 74 61 63 68 6D 65 6E 74 }   
      
   				 $s10 = { 67 65 74 4F 75 74 70 75 74 53 74 72 65 61 6D }   
      
   				 $s11 = { 70 61 67 65 43 6F 6E 74 65 78 74 2E }   
      
   				 $s12 = { 6F 75 74 2E 70 72 69 6E 74 6C 6E 28 22 6E 6F 22 29 }   
      
   				condition:   
      
   				 filesize < 10KB and all of them   
      
   				}