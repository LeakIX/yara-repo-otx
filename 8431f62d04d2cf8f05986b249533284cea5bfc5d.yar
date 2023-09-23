rule M_Hunting_ICO_Caffeine_Favicon_1   
   {   
    meta:   
    author = "adrian.mccabe"   
    md5 = "12e3dac858061d088023b2bd48e2fa96"   
    date_created = "2022-09-22"   
    rev = "1"   
    context = "Searches for legitimate Microsoft favicon used by Caffeine. VALIDATION REQUIRED."   
    strings:   
    $a1 = { 01 00 06 00 80 }   
    $a2 = "fffffff" ascii wide   
    $a3 = "3333333" ascii wide   
    $a4 = "DDDDDDDDDDDUUUUUUUUUUUP" ascii wide   
    $a5 = "UUUPDDD@" ascii wide   
    condition:   
    uint16(1) == 0x0100 and   
    all of them    
   }