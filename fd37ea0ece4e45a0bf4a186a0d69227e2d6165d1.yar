rule CISA_10400779_06 : credential_harvester ZIMBRA   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10400779"   
      
   				 Date = "2022-08-29"   
      
   				 Last_Modified = "20220908_1400"   
      
   				 Actor = "n/a"   
      
   				 Category = "Credential-Harvester"   
      
   				 Family = "ZIMBRA"   
      
   				 Description = "Detects ZIMBRA bash file samples"   
      
   				 MD5 = "ab28345b8aba13ae82f8bc0694f15804"   
      
   				 SHA256 = "d335d7e3a0ac77e132e9ea839591fa81f67cd8eef136ec6586a1d6b1f29e18f1"   
      
   				strings:   
      
   				 $s0 = "/opt/zimbra/bin/zmlocalconfig"   
      
   				 $s1 = { 7A 69 6D 62 72 61 5F 6C 64 61 70 5F 70 61 73 7377 6F 72 64 }   
      
   				 $s2 = { 7A 69 6D 62 72 61 5F 6C 64 61 70 5F 75 73 65 72 }   
      
   				 $s3 = { 7A 69 6D 62 72 61 5F 6C 64 61 70 5F 75 73 65 72 64 6E }   
      
   				 $s4 = { 6C 64 61 70 5F 75 72 6C }   
      
   				 $s5 = { 2D 73 20 7C 20 67 72 65 70 }   
      
   				 $s6 = { 6C 64 61 70 73 65 61 72 63 68 }   
      
   				 $s7 = { 75 73 65 72 73 2E 6C 64 69 66 }   
      
   				 $s8 = { 63 6F 6E 66 69 67 2E 6C 64 69 66 }   
      
   				 $s9 = { 73 65 72 76 69 63 65 2E 6C 64 69 66 }   
      
   				 $s10 = { 72 6D 20 2D 72 66 }   
      
   				 $s11 = { 2F 74 6D 70 2F 7A 69 6D 62 72 61 }   
      
   				 $s12 = { 74 65 73 74 2E 73 68 }   
      
   				 $s13 = { 74 65 73 74 2E 6A 73 70 }   
      
   				condition:   
      
   				 filesize < 10KB and all of them   
      
   				}