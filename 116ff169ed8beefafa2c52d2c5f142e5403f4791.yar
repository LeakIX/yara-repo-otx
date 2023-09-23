rule M_Hunting_JSON_Caffeine_Config_1   
   {   
    meta:   
    author = "adrian.mccabe"   
    md5 = "684b524cef81a9ef802ed3422700ab69"   
    date_created = "2022-09-22"   
    rev = "1"   
    context = "Searches for default Caffeine configuration syntax. Intentionally wide."   
    strings:   
    $cf1 = "token" ascii wide   
    $cf2 = "ip-api.io" ascii wide   
    $cf3 = "ff57341d-6fb8-4bdb-a6b9-a49f94cbf239" ascii wide   
    $cf4 = "send_to_telegram" ascii wide   
    $cf5 = "telegram_user_id" ascii wide   
    condition:   
    all of them   
   }