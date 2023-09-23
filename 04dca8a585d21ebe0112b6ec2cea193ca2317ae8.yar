rule SiennaPurple    
   {    
   	meta:    
           	author = "Microsoft Threat Intelligence Center (MSTIC)"    
   		description = "Detects PDB path, C2, and ransom note in DEV-0530 Ransomware SiennaPurple samples"    
   		hash = "99fc54786a72f32fd44c7391c2171ca31e72ca52725c68e2dde94d04c286fccd"    
   	strings:    
   		$s1 = "ForOP\\attack(utils)\\attack tools\\Backdoor\\powershell\\btlc_C\\Release\\btlc_C.pdb"    
   		$s2 = "matmq3z3hiovia3voe2tix2x54sghc3tszj74xgdy4tqtypoycszqzqd.onion"   
   		$s3 = "H0lyGh0st@mail2tor.com"   
   		$s4 = "We are <HolyGhost>. All your important files are stored and encrypted."   
   		$s5 = "aic^ef^bi^abc0"   
   		$s6 = "---------------------------3819074751749789153841466081"   
      
   	condition:    
   		uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and    
   		filesize < 7MB and filesize > 1MB and    
   		all of ($s*)    
   }