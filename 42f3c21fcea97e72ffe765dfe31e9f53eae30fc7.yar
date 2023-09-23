rule Zeppelin_1 {
   meta:
      description = "Zeppelin - from files cf9b6dda84cbf2dbfc6edd7a740f50bddc128842565c590d8126e5d93c024ff2, 0d22d3d637930e7c26a0f16513ec438243a8a01ea9c9d856acbcda61fcb7b499, e8596675fef4ad8378e4220c22f4358fdb4a20531b59d7df5382c421867520a9, a33e434ed9671b0bd3c2b0b2ee3e172dc4da119437fc28c77a190ca39469b4f0, 22c782b3923d755531ce3af704233c5acbe0780031f518143f010d853dbd66b0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-08-08"
      hash1 = "cf9b6dda84cbf2dbfc6edd7a740f50bddc128842565c590d8126e5d93c024ff2"
      hash2 = "0d22d3d637930e7c26a0f16513ec438243a8a01ea9c9d856acbcda61fcb7b499"
      hash3 = "e8596675fef4ad8378e4220c22f4358fdb4a20531b59d7df5382c421867520a9"
      hash4 = "a33e434ed9671b0bd3c2b0b2ee3e172dc4da119437fc28c77a190ca39469b4f0"
      hash5 = "22c782b3923d755531ce3af704233c5acbe0780031f518143f010d853dbd66b0"
   strings:
      $s1 = "6 6$6(6,6064686<6" fullword ascii /* hex encoded string 'ff`dhf' */
      $s2 = "=\"=3=D=~=" fullword ascii /* hex encoded string '=' */
      $s3 = "TThreadList," fullword ascii
      $s4 = "EVariantUnexpectedError\\" fullword ascii
      $s5 = ":!:%:M:W:\\:b:g:" fullword ascii
      $s6 = "TCustomVariantType8" fullword ascii
      $s7 = "TStringList8" fullword ascii
      $s8 = "TCustomMemoryStream<" fullword ascii
      $s9 = "TStringStream@" fullword ascii
      $s10 = "TPersistent," fullword ascii
      $s11 = "2\"252M2^2i2u2" fullword ascii
      $s12 = "4T4e4v4" fullword ascii
      $s13 = "8D8U8f8w8" fullword ascii
      $s14 = "; ;$;(;,;0;4;`;n;|;" fullword ascii
      $s15 = ".090C0" fullword ascii
      $s16 = ";T;e;v;" fullword ascii
      $s17 = "0,1I1}1" fullword ascii
      $s18 = "384=4d4l4{4" fullword ascii
      $s19 = ";&;+;8;X;r;w;H<" fullword ascii
      $s20 = ";+;8;G;T;c;p;" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}