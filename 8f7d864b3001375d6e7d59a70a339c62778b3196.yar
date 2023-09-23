rule APT_malware_2   
   {   
   meta:   
         description = "rule detects malware"   
         author = "other"   
   strings:   
         $api_hash = { 8A 08 84 C9 74 0D 80 C9 60 01 CB C1 E3 01 03 45 10 EB ED }   
         $http_push = "X-mode: push" nocase   
         $http_pop = "X-mode: pop" nocase   
   condition:   
         any of them   
   }