rule Zeppelin_9 {
   meta:
      description = "Zeppelin - from files 21807d9fcaa91a0945e80d92778760e7856268883d36139a1ad29ab91f9d983d, d618c1ccd24d29e911cd3e899a4df2625155297e80f4c5c1354bc2e79f70768c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-08-08"
      hash1 = "21807d9fcaa91a0945e80d92778760e7856268883d36139a1ad29ab91f9d983d"
      hash2 = "d618c1ccd24d29e911cd3e899a4df2625155297e80f4c5c1354bc2e79f70768c"
   strings:
      $s1 = "EFilerErrort" fullword ascii
      $s2 = "EWriteError$" fullword ascii
      $s3 = "TThread\\" fullword ascii
      $s4 = "EVariantBadVarTypeErrord" fullword ascii
      $s5 = "TStringListL" fullword ascii
      $s6 = "TStringsl" fullword ascii
      $s7 = "TStream," fullword ascii
      $s8 = "EInvalidPointer" fullword ascii
      $s9 = "EZeroDivide" fullword ascii
      $s10 = ": :$:(:,:0:4:H:h:p:t:x:|:" fullword ascii
      $s11 = "?4?=?X?k?~?" fullword ascii
      $s12 = ">)><>H>h>" fullword ascii
      $s13 = "?2?C?L?" fullword ascii
      $s14 = "3'3G3V3^3" fullword ascii
      $s15 = "=!=+=5=?=I=S=]=h=r=}=" fullword ascii
      $s16 = "4\"41484V4" fullword ascii
      $s17 = "=4=<=@=D=H=L=P=T=X=\\=l=" fullword ascii
      $s18 = "; ;$;,;0;8;<;D;H;P;T;\\;`;h;l;t;x;" fullword ascii
      $s19 = "4\"5:5L5d5" fullword ascii
      $s20 = "3!3/3S3" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}