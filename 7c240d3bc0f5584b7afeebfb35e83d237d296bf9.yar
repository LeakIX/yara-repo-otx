rule CrowdStrike_CSIT_14003_03 : installer    
      
   {    
      
          meta:    
      
                copyright = "CrowdStrike, Inc"    
      
                description = "Flying Kitten Installer"    
      
                version = "1.0"    
      
                actor = "FLYING KITTEN"    
      
                in_the_wild = true    
      
          strings:    
      
                $exename = "IntelRapidStart.exe"    
      
                $confname = "IntelRapidStart.exe.config"    
      
                $cabhdr = { 4d 53 43 46 00 00 00 00 }    
      
          condition:    
      
                all of them    
      
   }