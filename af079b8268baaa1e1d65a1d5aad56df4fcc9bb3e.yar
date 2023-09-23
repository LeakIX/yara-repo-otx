rule COLDSTEEL_service_strings   
   {   
       meta:   
           author = "NCSC"   
           reference = "NCSC/MAR/C/00025"   
           description = "Identifies the service created by COLDSTEEL."   
           date = "2023-01-31"   
           hash1 = "a94ed3d673261d62f2959979272d8c8d17e6e7f3"   
      
       strings:   
           $ = "msupdate"   
           $ = "Microsoft Update"   
           $ = "Enables the download and installation of Windows updates. If this service is disabled, this computer will not be able to use the Automatic Updates feature or the Windows Update Web site."   
      
       condition:   
           all of them   
   }