rule Zeppelin_4 {
   meta:
      description = "Zeppelin - from files 79d6e498e7789aaccd8caa610e8c15836267c6a668c322111708cf80bc38286c, bc214c74bdf6f6781f0de994750ba3c50c0e10d9db3483183bd47f5cef154509, 4728a3fa4f94d7a09e2dbe21d12ae84543042ce88ba4ea11f3fb3f27490a4933"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-08-08"
      hash1 = "79d6e498e7789aaccd8caa610e8c15836267c6a668c322111708cf80bc38286c"
      hash2 = "bc214c74bdf6f6781f0de994750ba3c50c0e10d9db3483183bd47f5cef154509"
      hash3 = "4728a3fa4f94d7a09e2dbe21d12ae84543042ce88ba4ea11f3fb3f27490a4933"
   strings:
      $s1 = "TImposterU" fullword ascii
      $s2 = "=\"=&=*=.=2=6=:=" fullword ascii /* hex encoded string '&' */
      $s3 = "EFOpenErrorH" fullword ascii
      $s4 = "EWriteErrorP" fullword ascii
      $s5 = "EThread," fullword ascii
      $s6 = ": :@:H:L:P:T:X:\\:`:d:h:x:" fullword ascii
      $s7 = "EVariantInvalidArgError," fullword ascii
      $s8 = "TStreamX" fullword ascii
      $s9 = "TStringListx" fullword ascii
      $s10 = "AAOri4" fullword ascii
      $s11 = "> >4><>@>D>H>L>P>T>X>\\>`>d>r>" fullword ascii
      $s12 = "? ?$?(?,?:?B?X?j?n?" fullword ascii
      $s13 = "Z=+&HFk" fullword ascii
      $s14 = "1\"2>2B2F2J2N2R2V2Z2^2b2f2j2n2r2v2z2~2" fullword ascii
      $s15 = "1I2g2}2" fullword ascii
      $s16 = "<\"<*<<<J<N<`<y<" fullword ascii
      $s17 = "=*=4=>=H=W=a=s= >9>`>l>p>" fullword ascii
      $s18 = "0F1s1 2d2r2" fullword ascii
      $s19 = "?,?4?8?<?@?D?H?L?P?T?X?\\?`?d?h?l?p?" fullword ascii
      $s20 = "232=2B2N2d2" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}