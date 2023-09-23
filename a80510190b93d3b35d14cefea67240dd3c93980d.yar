rule M_Hunting_JS_Caffeine_Redirect_1   
   {   
    meta:   
    author = "adrian.mccabe"   
    md5 = "60cae932b80378110d74fe447fa518d6"   
    date_created = "2022-09-22"   
    rev = "1"   
    context = "Searches for string artifacts on Caffeine Javascript redirect pages. Intentionally wide."   
    strings:   
    $cf1 = "Don't Play Here Kid" ascii wide   
    $cf2 = "mrxc0der" ascii wide   
    condition:   
    all of them   
   }