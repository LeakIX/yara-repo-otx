import "pe"
rule cobalt_strike_14435_dll_2 {   
      meta:   
         description = "32.dll"   
         author = "The DFIR Report"   
         reference = "https://thedfirreport.com"   
         date = "2022-09-12"   
         hash1 = "76bfb4a73dc0d3f382d3877a83ce62b50828f713744659bb21c30569d368caf8"   
      strings:   
         $x1 = "mail glide drooping dismiss collation production mm refresh murderer start parade subscription accident retorted carter stalls r" ascii   
         $s2 = "vlu405yd87.dll" fullword ascii   
         $s3 = "XYVZSWWVU" fullword ascii /* base64 encoded string 'aVRYeT' */   
         $s4 = "ZYWVWSXVT" fullword ascii /* base64 encoded string 'aeVIuS' */   
         $s5 = "WXVZTVVUVX" fullword ascii /* base64 encoded string 'YuYMUTU' */   
         $s6 = "ZYXZXSWZW" fullword ascii /* base64 encoded string 'avWIfV' */   
         $s7 = "SZWVSZTVU" fullword ascii /* base64 encoded string 'eeRe5T' */   
         $s8 = "VXVWUWVZYY" fullword ascii /* base64 encoded string 'UuVQeYa' */   
         $s9 = "VSXZZYSVU" fullword ascii /* base64 encoded string 'IvYa%T' */   
         $s10 = "VXUZUVWVU" fullword ascii /* base64 encoded string ']FTUeT' */   
         $s11 = "SVVZZXZUVW" fullword ascii /* base64 encoded string 'IUYevTU' */   
         $s12 = "USVZVSWVZ" fullword ascii /* base64 encoded string 'IVUIeY' */   
         $s13 = "SWVVTVSVWWXZZVVV" fullword ascii /* base64 encoded string 'YUSU%VYvYUU' */   
         $s14 = "VSXVUXXZS" fullword ascii /* base64 encoded string 'IuT]vR' */   
         $s15 = "WSVZYWZWWW" fullword ascii /* base64 encoded string 'Y%YafVY' */   
         $s16 = "XUSZXXVVW" fullword ascii /* base64 encoded string 'Q&W]UV' */   
         $s17 = "ZWZWZVZWWWZ" fullword ascii /* base64 encoded string 'efVeVVYf' */   
         $s18 = "STZVYVVZYS" fullword ascii /* base64 encoded string 'I6UaUYa' */   
         $s19 = "ZWZWYSZXUZ" fullword ascii /* base64 encoded string 'efVa&WQ' */   
         $s20 = "SVVWWVVVWW" fullword ascii /* base64 encoded string 'IUVYUUY' */   
      condition:   
         uint16(0) == 0x5a4d and filesize < 2000KB and   
         ( pe.imphash() == "4e03b8b675969416fb0d10e8ab11f7c2" or ( 1 of ($x*) or 12 of them ) )   
   }