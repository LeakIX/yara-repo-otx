rule tricklancer_c {    
       
     strings:    
       $str1 = "is_path_traversal_or_vpns_attack_request" nocase ascii wide    
       $str2 = "ns_vpn_process_unauthenticated_request" nocase ascii wide    
       $str3 = "mmapshell" nocase ascii wide    
       $str4 = "DoUnInject" nocase ascii wide    
       $str5 = "CalcDistanse" nocase ascii wide    
       $str6 = "checkMyData" nocase ascii wide    
       $str7 = "vpn_location_url_len" nocase ascii wide    
     condition:    
       5 of ($str*)    
   }