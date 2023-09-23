rule CISA_10398871_01 : trojan loader COBALTSTRIKE   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10398871"   
      
   				 Date = "2022-09-29"   
      
   				 Last_Modified = "20221001_1200"   
      
   				 Actor = "n/a"   
      
   				 Category = "Trojan Loader"   
      
   				 Family = "COBALTSTRIKE"   
      
   				 Description = "Detects CobaltStrike Loader samples"   
      
   				 MD5="058434852bb8e877069d27f452442167"   
      
   				 SHA256="25da610be6acecfd71bbe3a4e88c09f31ad07bdd252eb30feeef9debd9667c51"   
      
   				strings:   
      
   				 $s1 = { 62 69 6E 2E 63 6F 6E 66 69 67 }   
      
   				 $s2 = { 56 46 54 52 41 43 45 }   
      
   				 $s3 = { FF 15 18 D0 00 10 }   
      
   				 $s4 = { FF 15 28 D0 00 10 }   
      
   				 $s5 = { 8B 55 EC 03 55 F4 0F B6 02 33 45 E4 }   
      
   				condition:   
      
   				 uint16(0) == 0x5A4D and all of them   
      
   				}