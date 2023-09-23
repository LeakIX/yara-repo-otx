import "pe"
rule MAL_WarzoneRAT   
   {   
   meta:   
   author = "Insikt Group, Recorded Future"   
   date = "2022-08-22"   
   description = "Detects variants of WarzoneRAT"   
   version = "1.0"   
   hash = "44673a8ff098f12910c441c5697d27889dd1c5fd4aef875d4cf381227eac3a2b"   
   strings:   
   $s1 = "Ave_Maria" nocase ascii wide   
   $s2 = "127.0.0.2" fullword ascii   
   $s3 = "RDPClip" wide fullword   
   $s4 = "MaxConnectionsPer1_0Server" fullword ascii   
   $s5 = "MaxConnectionsPerServer" fullword ascii   
   $x1 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword   
   wide   
   $x2 = "/n:%temp%\\ellocnak.xml" fullword wide   
   $x3 = "Hey Im Admin" fullword wide   
   $x4 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " fullword ascii   
   $x5 = "XXXXXX" fullword ascii   
   $x6 = "%02d-%02d-%02d_%02d.%02d.%02d" fullword wide   
   $x7 = "POP3 Password" fullword wide   
   $x8 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" fullword wide   
   $x9 = "\\logins.json" fullword wide   
   $m1 = "C:\\Users\\Vitali Kremez\\Documents\\MidgetPorn\\workspace\\MsgBox.exe"   
   fullword wide   
   $m2 = "C:\\Users\\louis\\Documents\\workspace\\MortyCrypter\\MsgBox.exe" fullword   
   wide   
   condition:   
   uint16(0) == 0x5a4d   
   and for any i in (0..pe.number_of_sections):(pe.sections[i].name contains "BSS" or   
   pe.sections[i].name contains "bss")   
   and 4 of ($s*)   
   and 1 of ($m*)   
   and 3 of ($x*)   
   }