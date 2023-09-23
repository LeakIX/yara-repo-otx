rule bumblebee_13842_mkl2n_dll {   
       meta:   
          description = "BumbleBee - file mkl2n.dll"   
          author = "The DFIR Report via yarGen Rule Generator"   
          reference = "https://thedfirreport.com"   
          date = "2022-11-13"   
          hash1 = "f7c1d064b95dc0b76c44764cd3ae7aeb21dd5b161e5d218e8d6e0a7107d869c1"   
       strings:   
          $s1 = "pxjjqif723uf35.dll" fullword ascii   
          $s2 = "tenant unanimously delighted sail databases princess bicyclelist progress accused urge your science certainty dalton databases h" ascii   
          $s3 = "JEFKKDJJKHFJ" fullword ascii /* base64 encoded string '$AJ(2I(qI' */   
          $s4 = "KFFJJEJKJK" fullword ascii /* base64 encoded string '(QI$BJ$' */   
          $s5 = "JHJGKDFEG" fullword ascii /* base64 encoded string '$rF(1D' */   
          $s6 = "IDJIIDFHE" fullword ascii /* base64 encoded string ' 2H 1G' */   
          $s7 = "JHJFIHJJI" fullword ascii /* base64 encoded string '$rE rI' */   
          $s8 = "EKGJKKEFHKFFE" fullword ascii /* base64 encoded string '(bJ(AG(QD' */   
          $s9 = "FJGJFKGFF" fullword ascii /* base64 encoded string '$bE(aE' */   
          $s10 = "IFFKJGJFK" fullword ascii /* base64 encoded string ' QJ$bE' */   
          $s11 = "FKFJDIHJF" fullword ascii /* base64 encoded string '(RC rE' */   
          $s12 = "EKFJFdHFG" fullword ascii /* base64 encoded string '(REtqF' */   
          $s13 = "HJFJJdEdEIDK" fullword ascii /* base64 encoded string '$RItGD 2' */   
          $s14 = "KFJHKDJdIGF" fullword ascii /* base64 encoded string '(RG(2] a' */   
          $s15 = "magination provided sleeve governor earth brief favourite setting trousers phone calamity ported silas concede appearance abate " ascii   
          $s16 = "wK}zxspyuvqswyK" fullword ascii   
          $s17 = "stpKspyq~sqJvvvJ" fullword ascii   
          $s18 = "ntribute popped monks much number practiced dirty con mid nurse variable road unwelcome rear jeer addition distract surgeon fall" ascii   
          $s19 = "uvzrquxrrwxur" fullword ascii   
          $s20 = "vvvxvsqrs" fullword ascii   
       condition:   
          uint16(0) == 0x5a4d and filesize < 9000KB and   
          8 of them   
    }