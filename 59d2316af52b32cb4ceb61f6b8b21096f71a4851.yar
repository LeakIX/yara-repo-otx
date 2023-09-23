rule CISA_10400779_03 : trojan webshell backdoor   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10400779"   
      
   				 Date = "2022-08-29"   
      
   				 Last_Modified = "20220908_1400"   
      
   				 Actor = "n/a"   
      
   				 Category = "Trojan Webshell Backdoor"   
      
   				 Family = "n/a"   
      
   				 Description = "Detects malicious password protected JSP webshell samples"   
      
   				 MD5 = "0751fbc32ada4ded129a15a0d1ea0459"   
      
   				 SHA256 = "c8c1a0fae73b578480b15ff552499c271a1b49f7af2fb9fc7f8adaa4e984f614"   
      
   				strings:   
      
   				 $s0 = { 2E 65 71 75 61 6C 73 }   
      
   				 $s1 = { 67 65 74 50 61 72 61 6D 65 74 65 72 28 22 70 77 64 22 29 }   
      
   				 $s2 = { 2E 65 78 65 63 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 }   
      
   				 $s3 = { 2E 67 65 74 49 6E 70 75 74 53 74 72 65 61 6D }   
      
   				 $s4 = { 6F 75 74 2E 70 72 69 6E 74 28 }   
      
   				 $s5 = { 3C 70 72 65 3E }   
      
   				 $s6 = { 3C 2F 70 72 65 3E }   
      
   				condition:   
      
   				 filesize < 10KB and all of them   
      
   				}