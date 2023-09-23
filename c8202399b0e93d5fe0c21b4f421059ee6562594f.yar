rule beian_cc_phish : maldoc image   
   {   
     meta:   
       description = "Beian QR code phishing campaign"   
       author = "@stoerchl"   
       date = "2022-11-28"   
      
     strings:   
       $png_img_value_0 = {89504e470d0a1a0a0000000d494844520000000e0000000e08060000001f482dd10000001974455874536f6674776172650041646f626520496d616765526561647971c9653c0000032169545874584d4c3a636f6d2e}   
       $word_content = "word/document.xml"   
      
     condition:   
       all of them and uint32be(0) == 0x504b0304   
   }