rule CISA_10372500_02 : miner XMRIG   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10372500"   
      
   				 Date = "2022-03-03"   
      
   				 Last_Modified = "20220307_1600"   
      
   				 Actor = "n/a"   
      
   				 Category = "Miner"   
      
   				 Family = "XMRIG"   
      
   				 Description = "Detects XMRIG Miner samples"   
      
   				 MD5_1 = "f0cf1d3d9ed23166ff6c1f3deece19b4"   
      
   				 SHA256_1 = "0663d70411a20340f184ae3b47138b33ac398c800920e4d976ae609b60522b01"   
      
   				strings:   
      
   				 $s0 = { 58 4D 52 69 67 20 36 2E }   
      
   				 $s1 = { 63 6F 6E 66 69 67 5C 78 6D 72 69 67 2E 6A 73 }   
      
   				 $s2 = { 78 6D 72 69 67 2D 63 75 64 61 2E 64 6C 6C }   
      
   				 $s3 = { 6C 69 62 78 6D 72 69 67 2D }   
      
   				 $s4 = { 63 75 64 61 2E 73 6F }   
      
   				 $s5 = { 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F }   
      
   				 $s6 = { 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 }   
      
   				condition:   
      
   				 all of them   
      
   				}