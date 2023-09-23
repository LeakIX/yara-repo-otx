rule ClopELF   
   {   
   meta:   
   author = "@Tera0017/@SentinelLabs"   
   description = "Temp Clop ELF variant yara rule based on $hash"   
   reference = "https://s1.ai/Clop-ELF"   
   hash = "09d6dab9b70a74f61c41eaa485b37de9a40c86b6d2eae7413db11b4e6a8256ef"   
   strings:   
   $code1 = {C7 45 ?? 00 E1 F5 05}   
   $code2 = {81 7D ?? 00 E1 F5 05}   
   $code3 = {C7 44 24 ?? 75 00 00 00}   
   $code4 = {C7 44 24 ?? 80 01 00 00}   
   $code5 = {C7 00 2E [3] C7 40 04}   
   $code6 = {25 00 F0 00 00 3D 00 40 00 00}   
   $code7 = {C7 44 24 04 [4] C7 04 24 [4] E8 [4] C7 04 24 FF FF FF FF E8 [4] C9 C3}   
   condition:   
   uint32(0) == 0x464c457f and all of them   
   }