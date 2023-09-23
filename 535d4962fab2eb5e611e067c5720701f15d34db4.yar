rule M_Hunting_PHP_Caffeine_Toolmarks_1   
   {   
    meta:   
    author = "adrian.mccabe"   
    md5 = " ce9a17f9aec9bd2d9eca70f82e5e048b"   
    date_created = "2022-09-22"   
    rev = "1"   
    context = "Searches for generic Caffeine obfuscation toolmark strings. Intentionally wide."   
    strings:   
    $attacker_brand = " - WWW.CAFFEINES.STORE" ascii wide   
    $obfuscation_tagline = "CODED By MRxC0DER" ascii wide   
    condition:   
    all of them   
   }