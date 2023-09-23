rule CISA_10400779_04 : trojan webshell backdoor   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10400779"   
      
   				 Date = "2022-08-29"   
      
   				 Last_Modified = "20220908_1400"   
      
   				 Actor = "n/a"   
      
   				 Category = "Trojan Webshell Backdoor"   
      
   				 Family = "n/a"   
      
   				 Description = "Detects malicious JSP webshell samples"   
      
   				 MD5 = "e146561122214f67eb35c52758a21fa5"   
      
   				 SHA256 = "c24ead55e58422365f034d173bb0415c16be78928b2843ef8f6f62feb15e1553"   
      
   				strings:   
      
   				 $s0 = { 49 4E 50 55 54 20 6E 61 6D 65 }   
      
   				 $s1 = { 63 6D 64 }   
      
   				 $s2 = { 73 75 62 6D 69 74 20 76 61 6C 75 65 }   
      
   				 $s3 = { 52 75 6E }   
      
   				 $s4 = { 53 74 72 69 6E 67 20 63 6D 64 }   
      
   				 $s5 = { 67 65 74 50 61 72 61 6D 65 74 65 72 }   
      
   				 $s6 = { 53 74 72 69 6E 67 20 6F 75 74 70 75 74 }   
      
   				 $s7 = { 65 78 65 63 28 63 6D 64 }   
      
   				 $s8 = { 67 65 74 49 6E 70 75 74 53 74 72 65 61 6D }   
      
   				 $s9 = { 73 2B 22 3C 2F 62 72 3E 22 }   
      
   				 $s10 = { 70 72 69 6E 74 53 74 61 63 6B 54 72 61 63 65 }   
      
   				condition:   
      
   				 filesize < 10KB and all of them   
      
   				}