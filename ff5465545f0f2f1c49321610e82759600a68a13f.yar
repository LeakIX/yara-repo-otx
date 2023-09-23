rule cybercrime_Ransom_ShellScript_ESXi_Attacks : SH    
   {    
    meta:    
    description = "Rule to Detect Shell Script in ESXi Ransomware Attacks"    
    author = "The BlackBerry Research & Intelligence team"    
    distribution = "TLP:White"    
    version = "1.0"    
    last_modified = "2023-02-06"    
    md5 = "d0d36f169f1458806053aae482af5010"    
    sha256 = "10c3b6b03a9bf105d264a8e7f30dcab0a6c59a414529b0af0a6bd9f1d2984459"  strings:  $a1 = "KILL VMX" fullword nocase    
    $a2 = "START ENCRYPT:" fullword nocase    
    $a3 = "/bin/grep encrypt | /bin/grep -v grep" fullword nocase  condition:    
    uint16(0) == 0x2123 and filesize < 50KB and all of ($a*) }