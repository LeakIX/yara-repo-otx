import "pe"
rule COLDSTEEL_rundll32_use_and_export_names   
   {   
       meta:   
           author = "NCSC"   
           reference = "NCSC/MAR/C/00025"   
           description = "COLDSTEEL Themida import usage."   
           date = "2023-01-31"   
           hash1 = "9ec69a042106fc9d27a27197d3b680b468bca9a0"   
      
       strings:   
            $ = "rundll32.exe \"%s\",UpdateDriverForPlugAndPlayDevicesW"   
      
       condition:   
           all of them   
           and pe.exports("UpdateDriverForPlugAndPlayDevicesW")   
           and pe.exports("ServiceMain")   
           and pe.exports("DiUninstallDevice")   
   }