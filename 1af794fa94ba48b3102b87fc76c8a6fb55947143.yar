rule CISA_10400779_08 : trojan webshell   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10400779"   
      
   				 Date = "2022-08-29"   
      
   				 Last_Modified = "20220908_1400"   
      
   				 Actor = "n/a"   
      
   				 Category = "Trojan Webshell"   
      
   				 Family = "n/a"   
      
   				 Description = "Detects JSP Webshell command execution samples"   
      
   				 MD5 = "7153cfe57d2df499175aced7e92bcf65"   
      
   				 SHA256 = "ffb0f637776bc4cfcf5a24406ebf48fc21b9dcec68587a010f21b88250bda195"   
      
   				strings:   
      
   				 $s0 = { 67 65 74 50 61 72 61 6D 65 74 65 72 28 22 63 6D 64 22 29 }   
      
   				 $s1 = { 6F 75 74 2E 70 72 69 6E 74 6C 6E 28 22 43 6F 6D 6D 61 6E 64 }   
      
   				 $s2 = { 22 3C 42 52 3E 22 }   
      
   				 $s3 = { 67 65 74 50 72 6F 70 65 72 74 79 }   
      
   				 $s4 = { 22 6F 73 2E 6E 61 6D 65 22 }   
      
   				 $s5 = { 22 77 69 6E 64 6F 77 73 22 }   
      
   				 $s6 = { 63 6D 64 2E 65 78 65 20 2F 43 }   
      
   				 $s7 = { 4F 75 74 70 75 74 53 74 72 65 61 6D }   
      
   				 $s8 = { 6F 75 74 2E 70 72 69 6E 74 6C 6E 28 64 69 73 72 29 }   
      
   				condition:   
      
   				 all of them   
      
   				}