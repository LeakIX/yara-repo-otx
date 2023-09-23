rule M_Hunting_PHP_Caffeine_Obfuscation_1   
   {   
    meta:   
    author = "adrian.mccabe"   
    md5 = "ce9a17f9aec9bd2d9eca70f82e5e048b"   
    date_created = "2022-09-22"   
    rev = "1"   
    context = "Searches for obfuscated PHP scripts."   
    strings:   
    $f1 = {3C 3F 70 68 70 }   
    $a1 = "__FILE__));" ascii wide   
    $a2 = "=NULL;@eval" ascii wide   
    $a3 = "))));unset" ascii wide   
    condition:   
    uint16(0) == 0x3F3C and    
    all of them   
   }