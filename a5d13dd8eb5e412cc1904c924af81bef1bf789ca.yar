rule Gamaredon_Remote_Template{   
       meta:   
       description = "Detects Gamaredon remote template"   
       author = "BlackBerry Threat Research Team"   
       date = "2022-10-19-2021"   
   license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"   
       strings:   
           $s1 = "word/_rels/settings.xml.rels"   
           $s2 = "customXml/_rels/item1.xml.rels"   
           $s3 = "customXml/_rels/item2.xml.rels"   
           $s4 = "customXml/itemProps1.xml"   
           $s5 = "customXml/item1.xml"   
      
           $x = {77 6F 72 64 2F 5F 72 65 6C 73 2F 73 65 74 74 69   
           6E 67 73 2E 78 6D 6C 2E 72 65 6C 73 8D D0 BD 4E C4 30   
           0C 00 E0 1D 89 77 88 B2 DC 44 DD 1E 12 3A A1 A6 B7 00   
           D2 0D 2C A8 3C 80 D5 B8 6D 74 AD 13 12 17 B5 6F 4F 86   
           0E 9C C4 C0 E8 BF CF 96 EB F3 3A 4F EA 9B 62 72 9E 8D   
           AE 8A 52 2B E2 CE 5B C7 83 D1 9F ED DB C3 49 AB 24 C8   
           16 27 CF 64 F4 46 49 9F 9B FB BB FA 83 26 14 E7 39 8D   
           2E 24 95 15 4E 46 8F 22 E1 19 20 75 23 CD 98 0A 1F 88   
           73 A5 F7 71 46 C9 61 1C 20 60 77}   
      
       condition:   
           uint16(0) == 0x504d and all of them   
   }