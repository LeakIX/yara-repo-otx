rule Mal_Ransomware_Win32_DJVU_Payload    
   {    
    meta:    
    description = "Detects DJVU Ransomware Payload"    
    author = "BlackBerry Threat Research team"    
    date = "2022-09-09"    
    sha256 = "bd5114b7fcb628ba6f8c5c5d1d47fc7bb16214581079b3cc07273618b0c41fd8"    
    license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"  strings:    
    $a_nameserver_regex = /ns[0-9]?\.[a-z0-9]+\.[a-z]+/    
    $a_deny_perm = "/deny *S-1-1-0:(OI)(CI)(DE,DC)" wide    
    $a_pdb = "encrypt_win_api.pdb"  $a_arg1 = "--Admin" wide    
    $a_arg2 = "--AutoStart" wide    
    $a_arg3 = "IsAutoStart" wide    
    $a_arg4 = "IsNotAutoStart" wide    
    $a_arg5 = "IsTask" wide  $a_jpg = "5d2860c89d774.jpg" wide  $a_country_check = "country_code\":"    
       
    $a_c2_pid = "?pid=" wide    
    $a_c2_first = "&first=" wide  $a_scheduled_task = "Time Trigger Task" wide    
    $a_user_agent = "Microsoft Internet Explorer" wide  $mutex1 = "{1D6FC66E-D1F3-422C-8A53-C0BBCF3D900D}"    
    $mutex2 = "{FBB4BCC6-05C7-4ADD-B67B-A98A697323C1}"    
    $mutex3 = "{36A698B9-D67C-4E07-BE82-0EC5B14B4DF5}"  condition:    
    uint16(0) == 0x5a4d and    
     all of ($a*) and    
    1 of ($mutex*)  }