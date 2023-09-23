rule dingo_jspy_webshell   
      
   {   
      
   strings:   
      
   $string1 = "dingo.length"   
      
   $string2 = "command = command.trim"   
      
   $string3 = "commandAction"   
      
   $string4 = "PortScan"   
      
   $string5 = "InetAddress.getLocalHost"   
      
   $string6 = "DatabaseManager"   
      
   $string7 = "ExecuteCommand"   
      
   $string8 = "var command = form.command.value"   
      
   $string9 = "dingody.iteye.com"   
      
   $string10 = "J-Spy ver"   
      
   $string11 = "no permission ,die"   
      
   $string12 = "int iPort = Integer.parseInt"   
      
   condition:   
      
   filesize < 50KB and 12 of ($string*)   
      
   }