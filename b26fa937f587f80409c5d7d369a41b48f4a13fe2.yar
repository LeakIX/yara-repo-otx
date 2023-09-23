rule CISA_10398871_02 : trojan COBALTSTRIKE   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10398871"   
      
   				 Date = "2022-09-29"   
      
   				 Last_Modified = "20221001_1200"   
      
   				 Actor = "n/a"   
      
   				 Category = "Trojan"   
      
   				 Family = "COBALTSTRIKE"   
      
   				 Description = "Detects CobaltStrike trojan shellcode samples with an embedded beacon"   
      
   				 MD5="ff1d9474c2bfa9ada8d5ed3e16f0b04a"   
      
   				 SHA256="3450d5a3c51711ae4a2bdb64a896d312ba638560aa00adb2fc1ebc34bee9369e"   
      
   				strings:   
      
   				 $s1 = { 41 41 41 41 }   
      
   				 $s2 = { 42 42 42 42 }   
      
   				 $s3 = { 0F B6 45 10 8B 4D 08 03 4D FC 0F BE 11 33 D0 }   
      
   				 $s4 = { 8B 4D 08 51 6A 01 8B 55 C0 52 FF 55 C8 }   
      
   				condition:   
      
   				 uint16(9) == 0x5A4D and all of them   
      
   				}