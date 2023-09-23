rule Powerpoint_Code_Execution_87211_00007 {   
   meta:   
   author = "Cluster25"   
   description ="Detects Code execution technique in Powerpoint (Hyperlink and Action)"   
   hash1 = "d1bceccf5d2b900a6b601c612346fdb3fa5bb0e2faeefcac3f9c29dc1d74838d"   
   strings:   
   $magic = {D0 CF 11 E0 A1 B1 1A E1}   
   $s1 = "local.lnk" fullword wide   
   $s2 = "lmapi2.dll" fullword wide   
   $s3 = "rundll32.exe" fullword wide   
   $s4 = "InProcServer32" fullword wide   
   $s5 = "DownloadData" fullword wide   
   $s6 = "SyncAppvPublishingServer" fullword wide   
   condition: ($magic at 0) and (all of ($s*)) and filesize < 10MB    
   }