rule URSA_DLL_ENCRYPED_2022 {   
   meta:   
       description = "Yara rule for URSA trojan VBS loader AuToIT - September 2022 version"   
       author = "SI-LAB - https://seguranca-informatica.pt"   
       last_updated = "2022-09-14"   
       tlp = "white"   
       category = "informational"   
          
       strings:   
       $s_a = {15 62 70 67 18 1B 1A 1B 1C 21 1E 24}   
       $s_b = {32 33 34 35 36 37 38 2F 30 31 32 25 26 27 28 37 38 2F 30 31 32 33 34 35 36 37 38 2F 30 31 32 1B 1C 35 36}   
       condition:   
           filesize < 5000KB    
           and all of ($s_*)   
   }