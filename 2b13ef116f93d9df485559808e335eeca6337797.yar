rule tricklancer_a {    
       
     strings:    
       $str1 = "//var//log//ns.log" nocase ascii wide    
       $str2 = "//var//log//cron" nocase ascii wide    
       $str3 = "//var//log//auth.log" nocase ascii wide    
       $str4 = "//var//log//httpaccess-vpn.log" nocase ascii wide    
       $str5 = "//var//log//nsvpn.log" nocase ascii wide    
       $str6 = "TF:YYYYMMddhhmmss" nocase ascii wide    
       $str7 = "//var//log//lastlog" nocase ascii wide    
       $str8 = "clear_utmp" nocase ascii wide    
       $str9 = "clear_text_http" nocase ascii wide    
     condition:    
      7 of ($str*)    
   }