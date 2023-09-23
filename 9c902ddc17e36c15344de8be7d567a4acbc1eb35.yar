rule Zeppelin_28 {
   meta:
      description = "Zeppelin - from files 894b03ed203cfa712a28ec472efec0ca9a55d6058115970fe7d1697a3ddb0072, f2ad2b40a1ca4c337396cf8dd0528796c1e1657d8c76c441f459ac0e1dc60396"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-08-08"
      hash1 = "894b03ed203cfa712a28ec472efec0ca9a55d6058115970fe7d1697a3ddb0072"
      hash2 = "f2ad2b40a1ca4c337396cf8dd0528796c1e1657d8c76c441f459ac0e1dc60396"
   strings:
      $s1 = "ezX#PfS:>+" fullword ascii
      $s2 = "$Nz<3D" fullword ascii
      $s3 = "i<q=:u" fullword ascii
      $s4 = "JJ95na" fullword ascii
      $s5 = "ZVc+T%" fullword ascii
      $s6 = "n,U\"Z,I" fullword ascii
      $s7 = "Yw&5gLe" fullword ascii
      $s8 = "]u7y$9G" fullword ascii
      $s9 = "p]_qMx" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( all of them )
      ) or ( all of them )
}