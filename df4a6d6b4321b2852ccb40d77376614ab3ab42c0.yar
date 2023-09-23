rule malware_bumblebee_packed {    
       meta:    
           author = "Marc Salinas @ CheckPoint Research"    
           malware_family = "BumbleBee"    
           date = "13/07/2022"    
           description = "Detects the packer used by bumblebee, the rule is based on the code responsible for allocating memory for a critical structure in its logic."    
        
           dll_jul = "6bc2ab410376c1587717b2293f2f3ce47cb341f4c527a729da28ce00adaaa8db"    
           dll_jun = "82aab01a3776e83695437f63dacda88a7e382af65af4af1306b5dbddbf34f9eb"    
           dll_may = "a5bcb48c0d29fbe956236107b074e66ffc61900bc5abfb127087bb1f4928615c"    
           iso_jul = "ca9da17b4b24bb5b24cc4274cc7040525092dffdaa5922f4a381e5e21ebf33aa"    
           iso_jun = "13c573cad2740d61e676440657b09033a5bec1e96aa1f404eed62ba819858d78"    
           iso_may = "b2c28cdc4468f65e6fe2f5ef3691fa682057ed51c4347ad6b9672a9e19b5565e"    
           zip_jun = "7024ec02c9670d02462764dcf99b9a66b29907eae5462edb7ae974fe2efeebad"    
           zip_may = "68ac44d1a9d77c25a97d2c443435459d757136f0d447bfe79027f7ef23a89fce"    
        
       strings:    
           $heapalloc = {     
               48 8? EC [1-6]           // sub     rsp, 80h    
               FF 15 ?? ?? 0? 00 [0-5]  // call    cs:GetProcessHeap    
               33 D2                    // xor     edx, edx        ; dwFlags    
               4? [2-5]                 // mov     rcx, rax        ; hHeap    
               4? ?? ??                 // mov     r8d, ebx        ; dwBytes    
               FF 15 ?? ?? 0? 00        // call    cs:HeapAlloc    
               [8 - 11]                 // (load params)    
               48 89 05 ?? ?? ?? 00     // mov     cs:HeapBufferPtr, rax    
               E8 ?? ?? ?? ??           // call    memset    
               4? 8B ?? ?? ?? ?? 00     // mov     r14, cs:HeapBufferPtr    
           }     
        
       condition:    
           $heapalloc    
   }