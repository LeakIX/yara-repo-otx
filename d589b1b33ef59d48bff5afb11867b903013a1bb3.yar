rule CISA_10365227_02 : ClientUploader   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10365227"   
      
   				 Date = "2021-12-23"   
      
   				 Last_Modified = "20211224_1200"   
      
   				 Actor = "n/a"   
      
   				 Category = "n/a"   
      
   				 Family = "n/a"   
      
   				 Description = "Detects ClientUploader_mqsvn"   
      
   				 MD5_1 = "63cf36ac25788e13b41b1eb6bfc0c6b6"   
      
   				 SHA256_1 = "3585c3136686d7d48e53c21be61bb2908d131cf81b826acf578b67bb9d8e9350"   
      
   				strings:   
      
   				 $s1 = "UploadSmallFileWithStopWatch"   
      
   				 $s2 = "UploadPartWithStopwatch"   
      
   				 $s3 = "AppVClient"   
      
   				 $s4 = "ClientUploader"   
      
   				 $s5 = { 46 69 6C 65 43 6F 6E 74 61 69 6E 65 72 2E 46 69 6C 65 41 72 63 68 69 76 65 }   
      
   				 $s6 = { 4F 6E 65 44 72 69 76 65 43 6C 69 65 6E 74 2E 4F 6E 65 44 72 69 76 65 }   
      
   				condition:   
      
   				 uint16(0) == 0x5a4d and all of them   
      
   				}