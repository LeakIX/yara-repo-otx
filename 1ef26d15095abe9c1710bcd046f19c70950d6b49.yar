rule URSA_trojan_VBS_loader_2022 {   
   meta:   
       description = "Yara rule for URSA trojan VBS (loader) - September 2022 version"   
       author = "SI-LAB - https://seguranca-informatica.pt"   
       last_updated = "2022-09-14"   
       tlp = "white"   
       category = "informational"   
          
       strings:   
       $s_a = {6d 34 67 78 30 31}   
       $s_b = {6d 73 67 42 6f 78}   
       condition:   
           filesize < 10KB   
           and all of ($s_*)   
   }