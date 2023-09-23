rule MAL_Win_Ransomware_ViceSociety {   
     meta:   
       author = "Antonio Cocomazzi @ SentinelOne"   
       description = "Detect a custom branded version of Vice Society ransomware"   
       date = "2022-11-28"   
       reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development"   
       hash = "c8e7ecbbe78a26bea813eeed6801a0ac9d1eacac"   
      
     strings:   
       $code1 = {4? 8B ?? 28 00 02 00 }   
       $code2 = {4? C7 ?? 18 03 02 00 A3 00 00 00}   
       $code3 = {(48|49) 8D 8? 58 00 02 00}   
       $code4 = {(48|49) 8D 9? E8 02 02 00}   
       $code5 = {(48|4C) 89 ?? 24 38}   
       $code6 = {4? 8B ?? F8 02 02 00}   
       $code7 = {C7 44 24 48 01 00 00 00}   
       $string1 = "vsociet" nocase wide ascii   
      
     condition:   
       uint16(0) == 0x5A4D and all of them   
   }