rule URSA_VBS_AUTOIT_LOADER_2022 {   
   meta:   
       description = "Yara rule for URSA trojan VBS loader AuToIT - September 2022 version"   
       author = "SI-LAB - https://seguranca-informatica.pt"   
       last_updated = "2022-09-14"   
       tlp = "white"   
       category = "informational"   
          
       strings:   
       $s_a = "Nova"   
       $s_b = "_39"   
       $s_c = "FCYFLFCFMF"   
       $s_d = "FJCXCUCHCOCHEUFECWCHCOCHEUFECXCHCO"   
       condition:   
           filesize < 40KB   
           and all of ($s_*)   
   }