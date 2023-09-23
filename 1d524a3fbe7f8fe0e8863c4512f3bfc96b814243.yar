rule find_bat_14335 {   
   	meta:   
   		description = "Find.bat using AdFind"   
   		author = "The DFIR Report"   
   		reference = "https://thedfirreport.com"   
   		date = "2022-09-12"   
   		hash1 = "5bc00ad792d4ddac7d8568f98a717caff9d5ef389ed355a15b892cc10ab2887b"   
   	strings:   
   		$x1 = "find.exe" nocase wide ascii   
   				   
   		$s1 = "objectcategory" nocase wide ascii   
   		$s2 = "person" nocase wide ascii   
   		$s3 = "computer" nocase wide ascii   
   		$s4 = "organizationalUnit" nocase wide ascii   
   		$s5 = "trustdmp" nocase wide ascii   
   	condition:   
   		filesize < 1000   
   		and 1 of ($x*)   
   		and 4 of ($s*)   
   }