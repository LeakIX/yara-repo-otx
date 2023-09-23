import "hash"
rule URSA_AUTOIT_LOADER_2022 {   
   meta:   
       description = "Yara rule for URSA trojan VBS loader AuToIT - September 2022 version"   
       author = "SI-LAB - https://seguranca-informatica.pt"   
       last_updated = "2022-09-14"   
       tlp = "white"   
       category = "informational"   
          
       strings:   
       $s_a = {41 75 74 6F 49 74}   
       condition:   
           filesize < 900KB and   
           hash.md5(0, filesize) == "c56b5f0201a3b3de53e561fe76912bfd"    
           and all of ($s_*)   
   }