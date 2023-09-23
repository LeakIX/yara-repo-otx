rule  dbcode86mk_encrypted {   
   	meta:   
   		author = "eSentire TI"   
   		date = "04/27/2022"   
   		version = "1.0"   
   	strings:   
   		$a = {4B 65 77 44 72 69 76 65 72 33 32 48}   
   		$a1 = "KewDriver32H"   
   	condition:   
   		1 of ($a*) and (filesize<500KB)    
   }