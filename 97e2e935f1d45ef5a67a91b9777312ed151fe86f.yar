rule SiennaBlue    
   {    
       	meta:    
   		author = "Microsoft Threat Intelligence Center (MSTIC)"    
   		description = "Detects Golang package, function, and source file names observed in DEV-0530 Ransomware SiennaBlue samples"    
   		hash1 = "f8fc2445a9814ca8cf48a979bff7f182d6538f4d1ff438cf259268e8b4b76f86"    
   		hash2 = "541825cb652606c2ea12fd25a842a8b3456d025841c3a7f563655ef77bb67219"   
   	strings:    
   		$holylocker_s1 = "C:/Users/user/Downloads/development/src/HolyLocker/Main/HolyLock/locker.go"   
   		$holylocker_s2 = "HolyLocker/Main.EncryptionExtension"   
   		$holylocker_s3 = "HolyLocker/Main.ContactEmail"   
   		$holylocker_s4 = "HolyLocker/communication.(*Client).GetPubkeyFromServer"   
   		$holylocker_s5 = "HolyLocker/communication.(*Client).AddNewKeyPairToIntranet"   
   		   
   		$holyrs_s1 = "C:/Users/user/Downloads/development/src/HolyGhostProject/MainFunc/HolyRS/HolyRS.go"   
   		$holyrs_s2 = "HolyGhostProject/MainFunc.ContactEmail"   
   		$holyrs_s3 = "HolyGhostProject/MainFunc.EncryptionExtension"   
   		$holyrs_s4 = "HolyGhostProject/Network.(*Client).GetPubkeyFromServer"   
   		$holyrs_s5 = "HolyGhostProject/Network.(*Client).AddNewKeyPairToIntranet"   
   		$s1 = "Our site : <b><a href=%s>H0lyGh0stWebsite"   
   		$s2 = ".h0lyenc"   
   		$go_prefix = "Go build ID:"   
   	condition:    
   		uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and    
   		filesize < 7MB and filesize > 1MB and    
   		$go_prefix and all of ($s*) and (all of ($holylocker_*) or all of ($holyrs_*))   
   }