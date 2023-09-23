rule  MSI_Installer {   
   	meta:   
   		author = "eSentire TI"   
   		date = "04/27/2022"   
   		version = "1.0"   
   	strings:   
   		$msi = {D0 CF 11 E0 A1 B1 1A E1}   
   		$a1 = "CTH3VNU8KZHDXY6YYCF9YV8OXGPW3P2APZPL"   
   		$a2 = {41 70 70 50 61 74 63 68 5C 41 63 70 73 65 6E 73 2E 64 6C 6C}   
   		$a3 = {73 65 6E 73 2E 64 6C 6C}   
   		$a4 = {5B 53 79 73 74 65 6D 46 6F 6C 64 65 72 5D}   
   	condition:   
   		all of ($a*) and ($msi) and (filesize<1MB)    
   }