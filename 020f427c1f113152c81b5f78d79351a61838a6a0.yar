rule cybercrime_Ransom_ESXi_Attacks : ELF    
   {    
    meta:    
    description = "Rule to Detect ELF ESXi Ransomware Attacks"    
    author = "The BlackBerry Research & Intelligence team"    
    distribution = "TLP:White"    
    version = "1.0"    
    last_modified = "2023-02-06"    
    md5 = "87b010bc90cd7dd776fb42ea5b3f85d3"    
    sha256 = "11b1b2375d9d840912cfd1f0d0d04d93ed0cddb0ae4ddb550a5b62cd044d6b66"  strings:  $a1 = "file size in bytes (for sparse files)" fullword nocase wide ascii    
    $a2 = "number of MB in encryption block" fullword nocase wide ascii    
    $a3 = "number of MB to skip while encryption" fullword nocase wide ascii  condition:    
    uint32(0) == 0x464C457F and filesize < 500KB and all of ($a*) }