rule qakbot_loader {   
      meta:   
         description = "qakbot loader - file WW.js"   
         author = "EclecticIQ Threat Research Team"   
         date = "2022-11-29"   
         hash1 = "c5df8f8328103380943d8ead5345ca9fe8a9d495634db53cf9ea3266e353a3b1"   
      strings:   
         $s1 = "s.shellexecute(\"regS\"+content, \"port\\\\resemblance.tmp\", \"\", \"open\", 1);" fullword ascii   
         $s2 = "var content = WScript.CreateObject(\"Scripting.FileSystemObject\").OpenTextFile(\"data.txt\", 1).ReadAll();" fullword ascii   
         $s3 = "var s = WScript.CreateObject(\"shell.application\");" fullword ascii   
         $s4 = "// SIG // kfFY2pbnF13DvPG3LVxrrk1Daq6tsskeyXyIaMiJ3iYa" fullword ascii   
         $s5 = "// SIG // 3kSPNrrfN2sRzFYsNfrFaWz8YOdU254qNZQfd9O/VjxZ" fullword ascii   
         $s6 = "// SIG // bS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQVIzNi5j" fullword ascii   
         $s7 = "// SIG // X5X6KYFKxAXcUee9UjzpnQvBt6n8P/ofwIQ0cnqVrB1e" fullword ascii   
         $s8 = "// SIG // k7RgVZSNNqfJionWlBYwDQYJKoZIhvcNAQEMBQAwezEL" fullword ascii   
         $s9 = "// SIG // CWaZWFwpo7kMpjA4PNBGNjV8nLruw9X5Cnb6fgUbQMqS" fullword ascii   
         $s10 = "// SIG // aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdS" fullword ascii   
         $s11 = "// SIG // AAIBAAIBAAIBADAhMAkGBSsOAwIaBQAEFPERsxo2fxFs" fullword ascii   
         $s12 = "// SIG // VR0gBEMwQTA1BgwrBgEEAbIxAQIBAwIwJTAjBggrBgEF" fullword ascii   
         $s13 = "// SIG // KCFEzS2PTiVwu5efksVCCFzw8w5LXEFuqHKfnbrjOacF" fullword ascii   
         $s14 = "// SIG // fbY2lBpq7YQvNHjuY8aqC7luOzFWYg4xvd2E3UORn5ol" fullword ascii   
         $s15 = "// SIG // nTgkKjhQOPMedU1KZW3r8Hm40HGzKLdo0PxmK8YzFzbx" fullword ascii   
         $s16 = "// SIG // NRN3BTNPYy64LeG/ZacEaxjYcfrMCPJtiZkQsa3bPizk" fullword ascii   
         $s17 = "// SIG // NenVetG1fwCuqZCqxX8BnBCxFvzMbhjcb2L+plCnuHu4" fullword ascii   
         $s18 = "// SIG // cQrHXD8SS1UbjifrmAmZyI2mz3fLYAwYXg2Llsp1EwV9" fullword ascii   
         $s19 = "// SIG // ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUg" fullword ascii   
         $s20 = "// SIG // BggrBgEFBQcwAoY4aHR0cDovL2NydC5zZWN0aWdvLmNv" fullword ascii   
      condition:   
         uint16(0) == 0x2a2f and filesize < 30KB and   
         1 of ($s*) and 4 of them   
   }