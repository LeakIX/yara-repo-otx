rule bumblebee_13842_StolenImages_Evidence_iso {   
       meta:   
          description = "BumbleBee - file StolenImages_Evidence.iso"   
          author = "The DFIR Report via yarGen Rule Generator"   
          reference = "https://thedfirreport.com"   
          date = "2022-11-13"   
          hash1 = "4bb67453a441f48c75d41f7dc56f8d58549ae94e7aeab48a7ffec8b78039e5cc"   
       strings:   
          $x1 = "$..\\..\\..\\..\\Windows\\System32\\cmd.exe*/c start rundll32.exe mkl2n.dll,kXlNkCKgFC\"%systemroot%\\system32\\imageres.dll" fullword wide   
          $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii   
          $x3 = "%windir%\\system32\\cmd.exe" fullword ascii   
          $x4 = "Gcmd.exe" fullword wide   
          $s5 = "pxjjqif723uf35.dll" fullword ascii   
          $s6 = "tenant unanimously delighted sail databases princess bicyclelist progress accused urge your science certainty dalton databases h" ascii   
          $s7 = "mkl2n.dll" fullword wide   
          $s8 = "JEFKKDJJKHFJ" fullword ascii /* base64 encoded string '$AJ(2I(qI' */   
          $s9 = "KFFJJEJKJK" fullword ascii /* base64 encoded string '(QI$BJ$' */   
          $s10 = "JHJGKDFEG" fullword ascii /* base64 encoded string '$rF(1D' */   
          $s11 = "IDJIIDFHE" fullword ascii /* base64 encoded string ' 2H 1G' */   
          $s12 = "JHJFIHJJI" fullword ascii /* base64 encoded string '$rE rI' */   
          $s13 = "EKGJKKEFHKFFE" fullword ascii /* base64 encoded string '(bJ(AG(QD' */   
          $s14 = "FJGJFKGFF" fullword ascii /* base64 encoded string '$bE(aE' */   
          $s15 = "IFFKJGJFK" fullword ascii /* base64 encoded string ' QJ$bE' */   
          $s16 = "FKFJDIHJF" fullword ascii /* base64 encoded string '(RC rE' */   
          $s17 = "EKFJFdHFG" fullword ascii /* base64 encoded string '(REtqF' */   
          $s18 = "HJFJJdEdEIDK" fullword ascii /* base64 encoded string '$RItGD 2' */   
          $s19 = "KFJHKDJdIGF" fullword ascii /* base64 encoded string '(RG(2] a' */   
          $s20 = "documents.lnk" fullword wide   
       condition:   
          uint16(0) == 0x0000 and filesize < 13000KB and   
          1 of ($x*) and 4 of them   
    }