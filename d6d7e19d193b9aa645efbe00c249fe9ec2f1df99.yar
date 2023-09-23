import "elf"
rule Kinsing_Malware   
   {   
   	meta:   
   		author = "Aluma Lavi, CyberArk"   
   		date = "22-01-2021"   
   		version = "1.0"   
   		hash = "d247687e9bdb8c4189ac54d10efd29aee12ca2af78b94a693113f382619a175b"   
   		description = "Kinsing/NSPPS malware"   
   	strings:   
   		$rc4_key = { 37 36 34 31 35 33 34 34 36 62 36 31 }   
   		$firewire = "./firewire -iL $INPUT --rate $RATE -p$PORT -oL $OUTPUT"   
   		$packa1 = "google/btree" ascii wide   
   		$packa2 = "kardianos/osext" ascii wide   
   		$packa3 = "kelseyhightower/envconfig" ascii wide   
   		$packa4 = "markbates/pkger" ascii wide   
   		$packa5 = "nu7hatch/gouuid" ascii wide   
   		$packa6 = "paulbellamy/ratecounter" ascii wide   
   		$packa7 = "peterbourgon/diskv" ascii wide   
   		$func1 = "main.RC4" ascii wide   
   		$func2 = "main.runTaskWithScan" ascii wide   
   		$func3 = "main.backconnect" ascii wide   
   		$func4 = "main.downloadAndExecute" ascii wide   
   		$func5 = "main.startCmd" ascii wide   
   		$func6 = "main.execTaskOut" ascii wide   
   		$func7 = "main.minerRunningCheck" ascii wide   
   	condition:   
   		(uint16(0) == 0x457F   
   		and not (elf.sections[0].size + elf.sections[1].size + elf.sections[2].size + elf.sections[3].size + elf.sections[4].size + elf.sections[5].size + elf.sections[6].size + elf.sections[7].size > filesize))   
   		and ($rc4_key   
   		or $firewire   
   		or all of ($packa*)   
   		or 4 of ($func*)   
   		)   
   }