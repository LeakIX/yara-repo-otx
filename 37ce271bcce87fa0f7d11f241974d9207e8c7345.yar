rule Zeppelin_25 {   
      meta:   
         description = "Zeppelin - from files a42185d506e08160cb96c81801fbe173fb071f4a2f284830580541e057f4423b, ac4f0a4c4c3c53e1ce700c0f0d44d8b4ec311846dc536e48a3e19f6079f9512e"   
         author = "yarGen Rule Generator"   
         reference = "https://github.com/Neo23x0/yarGen"   
         date = "2022-08-08"   
         hash1 = "a42185d506e08160cb96c81801fbe173fb071f4a2f284830580541e057f4423b"   
         hash2 = "ac4f0a4c4c3c53e1ce700c0f0d44d8b4ec311846dc536e48a3e19f6079f9512e"   
      strings:   
         $s1 = "V)%uvm" fullword ascii   
         $s2 = ">q,(+I" fullword ascii   
         $s3 = "Ps s*Y" fullword ascii   
         $s4 = "@}4{X%" fullword ascii   
         $s5 = "AMi8YA" fullword ascii   
         $s6 = "j|&4G@" fullword ascii   
         $s7 = "yjAK8|" fullword ascii   
         $s8 = "_0C?%*" fullword ascii   
      condition:   
         ( uint16(0) == 0x5a4d and filesize < 600KB and ( all of them )   
         ) or ( all of them )   
   }