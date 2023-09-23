rule MAL_Lin_Ransomware_RedAlert {   
     meta:   
       author = "Antonio Cocomazzi @ SentinelOne"   
       description = "Detect a linux ransomware variant dubbed as RedAlert"   
       date = "2022-11-28"   
       reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development"   
       hash = "da6a7e9d39f6a9c802bbd1ce60909de2b6e2a2aa"   
      
     strings:   
       $code1 = {BA 48 00 00 00 BE [4] BF [4] E8 [4] BA 48 00 00 00 BE [4] BF [4] E8}   
       $code2 = {BF [4] 66 [6] 6B 06 E8}   
       $code3 = {B9 02 00 00 00 [0-12] BE 14 00 00 00 BF}   
       $code4 = {49 81 FE 00 00 50 00 [0-12] 0F}   
       $code5 = {49 81 FE 00 00 40 06 [0-12] 0F}   
      
     condition:   
       uint32(0) == 0x464c457f and all of them   
   }