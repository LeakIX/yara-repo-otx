rule Windows_Trojan_BUGHATCH {   
       meta:   
           author = "Elastic Security"   
           creation_date = "2022-05-09"   
           last_modified = "2022-06-09"   
           license = "Elastic License v2"   
           os = "Windows"   
           arch = "x86"   
           category_type = "Trojan"   
           family = "BUGHATCH"   
           threat_name = "Windows.Trojan.BUGHATCH"   
           reference_sample = "b495456a2239f3ba48e43ef295d6c00066473d6a7991051e1705a48746e8051f"           
      
       strings:   
       $a1 = { 8B 45 ?? 33 D2 B9 A7 00 00 00 F7 F1 85 D2 75 ?? B8 01 00 00 00 EB 33 C0 }   
       $a2 = { 8B 45 ?? 0F B7 48 04 81 F9 64 86 00 00 75 3B 8B 55 ?? 0F B7 42 16 25 00 20 00 00 ?? ?? B8 06 00 00 00 EB ?? }   
       $a3 = { 69 4D 10 FD 43 03 00 81 C1 C3 9E 26 00 89 4D 10 8B 55 FC 8B 45 F8 0F B7 0C 50 8B 55 10 C1 EA 10 81 E2 FF FF 00 00 33 CA 8B 45 FC 8B 55 F8 66 89 0C 42 }   
        $c1 = "-windowstyle hidden -executionpolicy bypass -file"   
        $c2 = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"   
        $c3 = "ReflectiveLoader"   
        $c4 = "\\Sysnative\\"   
        $c5 = "TEMP%u.CMD"   
        $c6 = "TEMP%u.PS1"   
        $c7 = "\\TEMP%d.%s"   
        $c8 = "NtSetContextThread"   
        $c9 = "NtResumeThread"   
      
       condition:   
           any of ($a*) or 6 of ($c*)   
   }