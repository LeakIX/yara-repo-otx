rule LummaC2 {   
      
       meta:   
           author = "RussianPanda"   
           description = "LummaC2 Detection"   
      
       strings:   
           $p1="lid=%s&j=%s&ver"   
           $p2= {89 ca 83 e2 03 8a 54 14 08 32 54 0d 04}   
      
       condition:   
           all of them and filesize <= 500KB   
   }
