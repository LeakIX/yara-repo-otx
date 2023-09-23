rule Zeppelin_33 {   
      meta:   
         description = "Zeppelin - from files c080d7228471422cbd230849cd523292b2b0553a3f347677ca66f3e502591eb1, 42770c6589ccf83a6712aca6f9d990a0c24b664887d5f5dead5d5f123c7b7ef9, 7be32f7764079ba925ea88173a1059fb120a90b5f1d891e13969ce171c129b4b"   
         author = "yarGen Rule Generator"   
         reference = "https://github.com/Neo23x0/yarGen"   
         date = "2022-08-08"   
         hash1 = "c080d7228471422cbd230849cd523292b2b0553a3f347677ca66f3e502591eb1"   
         hash2 = "42770c6589ccf83a6712aca6f9d990a0c24b664887d5f5dead5d5f123c7b7ef9"   
         hash3 = "7be32f7764079ba925ea88173a1059fb120a90b5f1d891e13969ce171c129b4b"   
      strings:   
         $s1 = "MS Shell Dlg" fullword wide   
         $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii   
         $s3 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii   
         $s4 = "@.data" fullword ascii   
         $s5 = "O_^ZYX" fullword ascii   
         $s6 = "lstrcatA" fullword ascii   
      condition:   
         ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )   
         ) or ( all of them )   
   }