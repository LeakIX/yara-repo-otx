rule CISA_10365227_01 : APPSTORAGE   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10365227"   
      
   				 Date = "2021-12-23"   
      
   				 Last_Modified = "20211224_1200"   
      
   				 Actor = "n/a"   
      
   				 Category = "n/a"   
      
   				 Family = "APPSTORAGE"   
      
   				 Description = "Detects AppStorage_ntstatus_msexch samples"   
      
   				 MD5_1 = "c435d133b45783cce91a5d4e4fbe3f52"   
      
   				 SHA256_1 = "157a0ffd18e05bfd90a4ec108e5458cbde01015e3407b3964732c9d4ceb71656"   
      
   				 MD5_2 = "baa634fdd2b34956524b5519ee97b8a8"   
      
   				 SHA256_2 = "30191b3badf3cdbc65d0ffeb68e0f26cef10a41037351b0f562ab52fce7432cc"   
      
   				strings:   
      
   				 $s1 = "026B924DD52F8BE4A3FEE8575DC"   
      
   				 $s2 = "GetHDDId"   
      
   				 $s3 = "AppStorage"   
      
   				 $s4 = "AppDomain"   
      
   				 $s5 = "$1e3e5580-d264-4c30-89c9-8933c948582c"   
      
   				 $s6 = "hrjio2mfsdlf235d" wide   
      
   				condition:   
      
   				 uint16(0) == 0x5a4d and all of them   
      
   				}