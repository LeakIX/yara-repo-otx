rule CISA_10410305_01 : webshell   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10410305"   
      
   				 Date = "2022-10-24"   
      
   				 Last_Modified = "20221028_1730"   
      
   				 Actor = "n/a"   
      
   				 Family = "n/a"   
      
   				 Malware_Type = "Webshell"   
      
   				 Tool_Type = "n/a"   
      
   				 Capabilities = "n/a"   
      
   				 Description = "Detects JSP webshells"   
      
   				 MD5 = "6acf93001a61f325e17a6f0f49caf5d1"   
      
   				 SHA256 = "14bf0cbee88507fb016d01e3ced053858410c389be022d2aa4d075287c781c4a"   
      
   				strings:   
      
   				 $s0 = { 72 65 71 75 65 73 74 }   
      
   				 $s1 = { 67 65 74 50 61 72 61 6D 65 74 65 72 }   
      
   				 $s2 = { 50 72 6F 63 65 73 73 42 75 69 6C 64 65 72 }   
      
   				 $s3 = { 73 65 70 61 72 61 74 6F 72 43 68 61 72 }   
      
   				 $s4 = { 67 65 74 49 6E 70 75 74 53 74 72 65 61 6D }   
      
   				 $s5 = { 75 73 65 44 65 6C 69 6D 69 74 65 72 }   
      
   				 $s6 = { 72 65 73 70 6F 6E 73 65 }   
      
   				 $s7 = { 73 65 6E 64 45 72 72 6F 72 }   
      
   				 $s8 = { 39 39 }   
      
   				 $s9 = { 31 30 39 }   
      
   				 $s10 = { 31 30 30 }   
      
   				 $s11 = { 34 37 }   
      
   				 $s12 = { 36 37 }   
      
   				 $s13 = { 39 38 }   
      
   				 $s14 = { 31 30 35 }   
      
   				 $s15 = { 31 31 30 }   
      
   				 $s16 = { 39 37 }   
      
   				 $s17 = { 31 31 35 }   
      
   				 $s18 = { 31 30 34 }   
      
   				 $s19 = { 34 35 }   
      
   				condition:   
      
   				 all of them and #s8 >= 2 and #s11 >= 3 and #s13 >= 2   
      
   				}