rule brute_ratel   
   {   
       meta:   
           author = "Yoroi Malware ZLab"   
           description = "Rule for BruteRatel Badger"   
           last_updated = "2023-02-15"   
           tlp = "WHITE"   
           category = "informational"   
      
       strings:   
           $1 = {8079ffcc74584585c075044883e920448a094180f9e9740a448a41034180f8e97507ffc24531c0ebd731c04180f94c752f8079018b7529807902d175214180f8b8751b8079060075170fb64105c1e0084189c00fb641044409c001d0eb0231c0c3} // Checks Breakpoint (DLL)   
           $2 = {565389d34883ec2885db74644889cee8????????31c9ba????????4989c0e8????????448d430165488b142530000000488b5260488b4a30ba08000000ffd04885f6741c4885c0742731d20f1f4400000fb60c16880c104883c2014839d375f04883c4285b5ec3} // Shellcode   
       condition:   
           (uint16(0) == 0x5A4D or uint16(0) == 0x00E8 or uint16(0) == 0x8348) and ($1 or $2)   
   }