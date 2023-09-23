rule CISA_10452108_02 : WHIRLPOOL backdoor communicates_with_c2 installs_other_components   
      
   				{   
      
   				meta:   
      
   				 author = "CISA Code & Media Analysis"   
      
   				 incident = "10452108"   
      
   				 date = "2023-06-20"   
      
   				 last_modified = "20230804_1730"   
      
   				 actor = "n/a"   
      
   				 family = "WHIRLPOOL"   
      
   				 Capabilities = "communicates-with-c2 installs-other-components"   
      
   				 Malware_Type = "backdoor"   
      
   				 Tool_Type = "unknown"   
      
   				 description = "Detects malicious Linux WHIRLPOOL samples"   
      
   				 sha256_1 = "83ca636253fd1eb898b244855838e2281f257bbe8ead428b69528fc50b60ae9c"   
      
   				 sha256_2 = "8849a3273e0362c45b4928375d196714224ec22cb1d2df5d029bf57349860347"   
      
   				strings:   
      
   				 $s0 = { 65 72 72 6f 72 20 2d 31 20 65 78 69 74 }   
      
   				 $s1 = { 63 72 65 61 74 65 20 73 6f 63 6b 65 74 20 65 72 72 6f 72 3a 20 25 73 28 65 72 72 6f 72 3a 20 25 64 29 }   
      
   				 $s2 = { c7 00 20 32 3e 26 66 c7 40 04 31 00 }   
      
   				 $a3 = { 70 6c 61 69 6e 5f 63 6f 6e 6e 65 63 74 }   
      
   				 $a4 = { 63 6f 6e 6e 65 63 74 20 65 72 72 6f 72 3a 20 25 73 28 65 72 72 6f 72 3a 20 25 64 29 }   
      
   				 $a5 = { 73 73 6c 5f 63 6f 6e 6e 65 63 74 }   
      
   				condition:   
      
   				 uint32(0) == 0x464c457f and 4 of them   
      
   				}
