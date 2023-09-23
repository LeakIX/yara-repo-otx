import "pe"
rule LockBit_3_dll   
   {   
    meta:   
    author = "VMware TAU" //bdana   
    date = "2022-Oct-12"   
    description = "Identifies LockBit 3.0 DLL encryptor by exported function names."   
    rule_version = "1"   
    yara_version = "4.2.3"   
    exemplar_hash = "c2529655c36f1274b6aaa72911c0f4db7f46ef3a71f4b676c4500e180595cac6"   
    condition:   
    pe.exports("del") and   
    pe.exports("gdel") and   
    pe.exports("gdll") and   
    pe.exports("gmod") and   
    pe.exports("pmod") and   
    pe.exports("sdll") and   
    pe.exports("wdll")   
   }