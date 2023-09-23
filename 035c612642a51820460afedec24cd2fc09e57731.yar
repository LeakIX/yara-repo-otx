rule Zeppelin_39 {   
      meta:   
         description = "Zeppelin - from files 0d22d3d637930e7c26a0f16513ec438243a8a01ea9c9d856acbcda61fcb7b499, e8596675fef4ad8378e4220c22f4358fdb4a20531b59d7df5382c421867520a9, a33e434ed9671b0bd3c2b0b2ee3e172dc4da119437fc28c77a190ca39469b4f0, 22c782b3923d755531ce3af704233c5acbe0780031f518143f010d853dbd66b0, 7d8c4c742689c097ac861fcbf7734709fd7dcab1f7ef2ceffb4b0b7dec109f55"   
         author = "yarGen Rule Generator"   
         reference = "https://github.com/Neo23x0/yarGen"   
         date = "2022-08-08"   
         hash1 = "0d22d3d637930e7c26a0f16513ec438243a8a01ea9c9d856acbcda61fcb7b499"   
         hash2 = "e8596675fef4ad8378e4220c22f4358fdb4a20531b59d7df5382c421867520a9"   
         hash3 = "a33e434ed9671b0bd3c2b0b2ee3e172dc4da119437fc28c77a190ca39469b4f0"   
         hash4 = "22c782b3923d755531ce3af704233c5acbe0780031f518143f010d853dbd66b0"   
         hash5 = "7d8c4c742689c097ac861fcbf7734709fd7dcab1f7ef2ceffb4b0b7dec109f55"   
      strings:   
         $s1 = "EZeroDivide$~@" fullword ascii   
         $s2 = "TFileStreamho@" fullword ascii   
         $s3 = "TStream|n@" fullword ascii   
         $s4 = "t~hDzC" fullword ascii   
         $s5 = "tEh|zC" fullword ascii   
      condition:   
         ( uint16(0) == 0x5a4d and filesize < 600KB and ( all of them )   
         ) or ( all of them )   
   }