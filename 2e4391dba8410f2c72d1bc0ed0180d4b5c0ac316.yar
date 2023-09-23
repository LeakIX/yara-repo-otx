rule M_APT_Kopiluwak_Recon_1   
   {   
    meta:   
    author = "Mandiant"   
    strings:   
    $rc4_1 = ".charCodeAt(i %"   
    $rc4_2 = ".length)) % 256"   
    $b64_1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"   
    $b64_3 = ".charAt(parseInt("   
    $recon_1 = "WScript.CreateObject"   
    $recon_2 = ".Run("   
    $Arguments = "WScript.Arguments"   
    condition:   
    ($rc4_1 and $rc4_2 and $b64_1) and ($Arguments or ($b64_3 and $recon_1 and $recon_2))   
   }