import "pe"
rule MsApp {   
   	meta:   
   		author = "eSentire TI"   
   		date = "04/27/2022"   
   		version = "1.0"   
   	strings:   
   		$a1 = "KewService32.dll"   
   		$a2 = ".vmp1"   
   		$a3 = {2E 76 6D 70 30}   
   		$a4 = {56 69 72 74 75 61 6C 42 6F 78}   
   	condition:   
   		3 of ($a*) and (filesize<11MB)   
   		and pe.exports("ServiceMain")   
   		and (uint16(0) == 0x5A4D or uint32(0) == 0x4464c457f)   
   }