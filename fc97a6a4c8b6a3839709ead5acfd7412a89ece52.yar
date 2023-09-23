rule p_bat_14335 {   
      meta:   
           description = "Finding bat files that is used for enumeration"   
   	    author = "The DFIR Report"   
   		reference = "https://thedfirreport.com"   
   		date = "2022-09-12"     
      
      
      strings:   
           				   
   		$a1 = "for /f %%i in" nocase wide ascii   
   		$a2 = "do ping %%i" nocase wide ascii   
   		$a3 = "-n 1 >>" nocase wide ascii   
   		$a4 = "res.txt" nocase wide ascii		   
       
     condition:   
         filesize < 2000KB   
         and all of ($a*)   
   }