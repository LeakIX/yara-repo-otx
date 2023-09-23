rule LockBit_Green {   
       meta:   
           author = "PRODAFT"   
           description = "LockBit Green detector (x32/x64)"   
           date = "2023-01-30"   
           rule_version = "v1"   
           malware_type = "ransomware"   
           tlp = "White"   
      
       strings:   
           $ransom_extension = {80 b6 98 68 63 00 78 ba 0f 00 00 00 6a 6a 68 ?? ?? ?? ?? 46 e8 ?? ?? ?? ?? 83 c4 08 68 ?? ?? ?? ?? ff d0 3b f0 72 ??}   
           $api_hashing_arithmetic = {42 0F B6 4C 05 AC B8 75  00 00 00 2B C1 8D 0C 80 B8 09 04 02 81 C1 E1 03  F7 E9 03 D1 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2  7F 2B C8 B8 09 04 02 81 83 C1 7F F7 E9 03 D1 C1  FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 2B}   
           $api_hashing_arithmetic_2 = {8A 44 34 15 B9 4B 00 00  00 0F B6 C0 2B C8 6B C1 1B 99 F7 FF 8D 42 7F 99  F7 FF 88 54 34 15}   
           $api_hashing_arithmetic_3 = {8a 44 0d ad 0f b6 c0  83 e8 06 6b c0 19 99 f7 ff 8d 42 7f 99 f7 ff 88 54 0d ad}   
           $api_hashing_arithmetic_4 = {42 0F B6 4C 05 E1 B8 39  00 00 00 2B C1 8D 0C 80 B8 09 04 02 81 C1 E1 03  F7 E9 03 D1 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2  7F 2B C8 B8 09 04 02 81 83 C1 7F F7 E9 03 D1 C1  FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 2B C8 42 88  4C 05 E1}   
      
       condition:   
           any of them and filesize < 260KB   
   }