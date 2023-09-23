rule RisePro_stealer {   
      
   meta:   
      
    version = "1.0"   
      
    malware = "RisePro"   
      
    description = "RisePro Stealer detection base on deobfuscation routine repetition"   
      
    source = "SEKOIA.IO"   
      
    classification = "TLP:GREEN"   
      
   strings:   
      
    $pxor = {66 0f ef 85}     // invoke xor between key and data   
      
    $mov_dword_ptr1 = {c7 85}   // one way to load data   
      
    $mov_dword_ptr2 = {c7 45}   // one way to load data   
      
   condition:   
      
    uint16be(0) == 0x4d5a and #mov_dword_ptr1 > 5000 and #mov_dword_ptr2 > 800 and #pxor > 1000   
      
   }