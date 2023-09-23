rule CISA_10365227_03 : ClientUploader   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10365227"   
      
   				 Date = "2021-12-23"   
      
   				 Last_Modified = "20211224_1200"   
      
   				 Actor = "n/a"   
      
   				 Category = "n/a"   
      
   				 Family = "n/a"   
      
   				 Description = "Detects ClientUploader_onedrv"   
      
   				 MD5_1 = "806998079c80f53afae3b0366bac1479"   
      
   				 SHA256_1 = "84164e1e8074c2565d3cd178babd93694ce54811641a77ffdc8d1084dd468afb"   
      
   				strings:   
      
   				 $s1 = "Decoder2"   
      
   				 $s2 = "ClientUploader"   
      
   				 $s3 = "AppDomain"   
      
   				 $s4 = { 5F 49 73 52 65 70 47 ?? 44 65 63 6F 64 65 72 73 }   
      
   				 $s5 = "LzmaDecoder"   
      
   				 $s6 = "$ee1b3f3b-b13c-432e-a461-e52d273896a7"   
      
   				condition:   
      
   				 uint16(0) == 0x5a4d and all of them   
      
   				}