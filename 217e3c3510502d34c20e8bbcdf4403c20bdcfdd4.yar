rule CISA_10400779_01 : trojan webshell GODZILLA   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10400779"   
      
   				 Date = "2022-08-29"   
      
   				 Last_Modified = "20220908_1400"   
      
   				 Actor = "n/a"   
      
   				 Category = "Trojan Webshell"   
      
   				 Family = "GODZILLA"   
      
   				 Description = "Detects Godzilla webshell samples"   
      
   				 MD5 = "2847c3be246be1dfd49789ebbffd5553"   
      
   				 SHA256 = "c602db153f48ab6580e5e85925677780c3d5a483c66c392a8ab8265aa108a409"   
      
   				strings:   
      
   				 $s0 = { 53 74 72 69 6E 67 20 78 63 }   
      
   				 $s1 = { 53 74 72 69 6E 67 20 70 61 73 73 }   
      
   				 $s2 = { 6D 64 35 28 70 61 73 73 2B 78 63 29 }   
      
   				 $s3 = { 43 6C 61 73 73 4C 6F 61 64 65 72 }   
      
   				 $s4 = { 53 65 63 72 65 74 4B 65 79 53 70 65 63 }   
      
   				 $s5 = { 4D 65 73 73 61 67 65 44 69 67 65 73 74 }   
      
   				 $s6 = { 62 61 73 65 36 34 }   
      
   				 $s7 = { 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 }   
      
   				 $s8 = { 73 65 73 73 69 6F 6E 2E 73 65 74 41 74 74 72 69 62 75 74 65 }   
      
   				condition:   
      
   				 filesize < 10KB and all of them   
      
   				}