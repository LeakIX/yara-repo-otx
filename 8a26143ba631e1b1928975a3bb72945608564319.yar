rule LucaStealer {    
    meta:    
    description = "Detects Luca Stealer"    
    author = "BlackBerry Threat Research Team"    
    date = "2022-08-06"    
    license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"  strings:  $s1 = "\\logsxc\\passwords_.txt" ascii wide    
    $s2 = "\\logsxc\\cookies_" ascii wide    
    $s3 = "\\logsxc\\telegram\\" ascii wide    
    $s4 = "\\logsxc\\sensfiles.zip" ascii wide    
    $s5 = "\\screen-.png" ascii wide    
    $s6 = "\\system_info.txt" ascii wide    
    $s7 = "out.zip" ascii wide    
    $s8 = "\\info.txt" ascii wide    
    $s9 = "\\system_info.txt"    
    $s10 = "data.png\\screen-1.png"    
    $s11 = "\\dimp.sts"    
    $s12 = "Credit Cards:"    
    $s13 = "Wallets:"  condition:    
    (    
    //PE File    
    uint16(0) == 0x5a4d and  //All Strings    
    12 of ($s*) )    
   }