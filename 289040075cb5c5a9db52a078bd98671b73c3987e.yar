rule MAL_Win_Ransomware_PolyVice {   
     meta:   
       author = "Antonio Cocomazzi @ SentinelOne"   
       description = "Detect a windows ransomware variant tracked as PolyVice adopted by multiple threat actors"   
       date = "2022-11-28"   
       reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development"   
       hash1 = "c8e7ecbbe78a26bea813eeed6801a0ac9d1eacac"   
       hash2 = "6cfb5b4a68100678d95270e3d188572a30abd568"   
       hash3 = "2b3fea431f342c7b8bcff4b89715002e44d662c7"   
      
     strings:   
       $code1 = {4? 8B ?? 28 00 02 00 }   
       $code2 = {4? C7 ?? 18 03 02 00 A3 00 00 00}   
       $code3 = {(48|49) 8D 8? 58 00 02 00}   
       $code4 = {(48|49) 8D 9? E8 02 02 00}   
       $code5 = {(48|4C) 89 ?? 24 38}   
       $code6 = {4? 8B ?? F8 02 02 00}   
       $code7 = {C7 44 24 48 01 00 00 00}   
      
     condition:   
       uint16(0) == 0x5A4D and all of them   
   }