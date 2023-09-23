rule M_Hunting_Script_LaunchAndDelete_1   
   {   
    meta:   
    author = "Mandiant"   
    md5 = "bd6e38b6ff85ab02c1a4325e8af29ce4"   
    description = "Finds scripts that launch and then delete files, indicative of cleaning up tracks and remaining in-memory only."   
    strings:   
    $ss = /setsid[^\n\r]{,250}-i[\r\n]{,5}rm/   
    condition:   
    all of them   
   }