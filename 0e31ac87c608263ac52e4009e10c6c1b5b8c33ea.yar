rule CISA_10454006_12 : SEASPRAY trojan evades_av   
      
   				{   
      
   				meta:   
      
   				 author = "CISA Code & Media Analysis"   
      
   				 incident = "10454006"   
      
   				 date = "2023-08-23"   
      
   				 last_modified = "20230905_1500"   
      
   				 actor = "n/a"   
      
   				 family = "SEASPRAY"   
      
   				 capabilities = "evades-av"   
      
   				 malware_type = "trojan"   
      
   				 tool_type = "unknown"   
      
   				 description = "Detects SEASPRAY samples"   
      
   				 sha256 = "44e1fbe71c9fcf9881230cb924987e0e615a7504c3c04d44ae157f07405e3598"   
      
   				strings:   
      
   				 $s1 = { 6f 73 2e 65 78 65 63 75 74 65 28 27 73 61 73 6c 61 75 74 63 68 64 27 }   
      
   				 $s2 = { 73 65 6e 64 65 72 }   
      
   				 $s3 = { 73 74 72 69 6e 67 2e 66 69 6e 64 }   
      
   				 $s4 = { 73 74 72 69 6e 67 2e 6c 6f 77 65 72 }   
      
   				 $s5 = { 62 6c 6f 63 6b 2f 61 63 63 65 70 74 }   
      
   				 $s6 = { 72 65 74 75 72 6e 20 41 63 74 69 6f 6e 2e 6e 65 77 7b }   
      
   				 $s7 = { 4c 69 73 74 65 6e 65 72 2e 6e 65 77 7b }   
      
   				condition:   
      
   				 filesize < 10KB and all of them   
      
   				}
