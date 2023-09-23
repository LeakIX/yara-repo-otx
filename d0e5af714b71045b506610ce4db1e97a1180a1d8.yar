rule M_Hunting_Python_Backdoor_CommandParser_1   
   {   
    meta:   
   author = "Mandiant"   
    md5 = "61ab3f6401d60ec36cd3ac980a8deb75"   
    description = "Finds strings indicative of the vmsyslog.py python backdoor."   
    strings:   
    $key1 = "readInt8()" ascii wide   
    $key2 = "upload" ascii wide   
    $key3 = "download" ascii wide   
    $key4 = "shell" ascii wide   
    $key5 = "execute" ascii wide   
    $re1 = /def\srun.{,20}command\s?=\s?self\.conn\.readInt8\(\).{,75}upload.{,75}download.{,75}shell.{,75}execute/s   
    condition:   
    filesize < 200KB and all of them   
   }