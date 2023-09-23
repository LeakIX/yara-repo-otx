import "pe"
rule apt_tontoteam__bisonal_doublet   
   {   
       meta:   
           author = "Dmitry Kupin"   
           company = "Group-IB"   
           description = "Detects Bisonal.DoubleT samples"   
           date = "2022-06-20"   
           hash = "58c1cab2a56ae9713b057626953f8967c3bacbf2cda68ce104bbb4ece4e35650"   
      
       strings:   
           $s0 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" fullword ascii   
           $s1 = "{\"status\":\"success\"}" fullword ascii   
           $s2 = "GetNativeSystemInfo" fullword ascii   
           $s3 = "::Off" fullword ascii   
           $s4 = "::On" fullword ascii   
      
       condition:   
           all of ( $s* ) or pe.imphash ( ) == "2edcf20dae8aede04f118ccf201f5bd2" or pe.imphash ( ) == "7f112e0b3c0a7ba76132c94ad9501c2a" or pe.imphash ( ) == "99dd7d50528327476d4b7badce66aff1" or pe.imphash ( ) == "7f112e0b3c0a7ba76132c94ad9501c2a"   
   }