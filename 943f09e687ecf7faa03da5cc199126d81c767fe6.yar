rule CISA_10400779_02 : utility ZIMBRA   
      
   				{   
      
   				meta:   
      
   				 Author = "CISA Code & Media Analysis"   
      
   				 Incident = "10400779"   
      
   				 Date = "2022-08-29"   
      
   				 Last_Modified = "20220908_1400"   
      
   				 Actor = "n/a"   
      
   				 Category = "Utility"   
      
   				 Family = "ZIMBRA"   
      
   				 Description = "Detects malicious JSP Zimbra samples"   
      
   				 MD5 = "36cfcfb4e6988caf8e449a7f26c92eae"   
      
   				 SHA256 = "28b7896bf81c5bcbe63c59ee7bfce3893894d93699949f59884834077694bd52"   
      
   				strings:   
      
   				 $s0 = { 2F 62 69 6E 2F 73 68 }   
      
   				 $s1 = { 22 72 6D 20 2D 72 66 }   
      
   				 $s2 = { 2F 76 61 72 2F 74 6D 70 2F 74 6D 70 2E 6A 61 72 }   
      
   				 $s3 = { 74 61 72 20 63 7A 66 }   
      
   				 $s4 = { 61 63 63 6F 75 6E 74 73 2E 78 6D 6C }   
      
   				 $s5 = { 6C 6F 63 61 6C 63 6F 6E 66 69 67 2E 78 6D 6C }   
      
   				 $s6 = { 2E 65 78 65 63 28 63 31 }   
      
   				 $s7 = { 2E 65 78 65 63 28 63 32 }   
      
   				 $s8 = { 2E 65 78 65 63 28 63 33 }   
      
   				condition:   
      
   				 filesize < 10KB and all of them   
      
   				}