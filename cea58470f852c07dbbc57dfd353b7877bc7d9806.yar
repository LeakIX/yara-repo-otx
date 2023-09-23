rule tricklancer_b {    
       
     strings:    
       $str1 = "nsppe" nocase ascii wide    
       $str2 = "pb_policy -h nothing" nocase ascii wide    
       $str3 = "pb_policy -d" nocase ascii wide    
       $str4 = "findProcessListByName" nocase ascii wide    
       $str5 = "restoreStateAndDetach" nocase ascii wide    
       $str6 = "checktargetsig" nocase ascii wide    
       $str7 = "DoInject" nocase ascii wide    
       $str8 = "DoUnInject" nocase ascii wide    
     condition:    
       7 of ($str*)    
   }