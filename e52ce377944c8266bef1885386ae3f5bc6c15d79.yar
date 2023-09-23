rule Stairwell_Exmatter_01 : ransomware dotnet   
   {   
      
   meta:   
      
   author = "Daniel Mayer (daniel@stairwell.com)"   
   copyright = "(c) 2022 Stairwell, Inc."   
   description = "Cleartext strings from an unobfuscated sample of Exmatter"   
   last_modified = "2022-08-23"   
   version = "0.1"   
      
   strings:   
      
   // Status strings   
   $ = "Commercial use only!" wide   
   $ = "We have {0} to upload and {1} completed" wide   
   $ = "Sending a report..." wide   
   // PowerShell used to end the process   
   $ = "-C \"Stop-Process -Id {0}; Start-Sleep 3; Set-Content -Path '{1}' -Value 0\"" wide   
      
   condition:   
      
   2 of them   
      
   }