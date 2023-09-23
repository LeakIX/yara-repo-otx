rule COLDSTEEL_strings   
   {   
       meta:   
           author = "NCSC"   
           reference = "NCSC/MAR/C/00025"   
           description = "COLDSTEEL strings"   
           date = "2023-01-31"   
           hash1 = "a94ed3d673261d62f2959979272d8c8d17e6e7f3"   
      
       strings:   
           $ = "MileStone201"   
           $ = "%SystemRoot%\\System32\\svchost.exe -k "   
           $ = "%s SP%d"   
           $ = "Win 2003"   
           $ = "Win 98"   
           $ = "RegSetValueEx(Svchost\\krnlsrvc)"   
           $ = "RegOpenKeyEx(Svchost)"   
           $ = "RegSetValueEx(ServiceDll)"   
      
       condition:   
           7 of them   
   }