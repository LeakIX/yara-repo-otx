import "pe"
rule LockBit_3_exe   
   {   
    meta:   
    author = "VMware TAU" //bdana   
    date = "2022-Oct-12"   
    description = "Identifies LockBit 3.0 exe encryptor section names, and artifact section names."   
    rule_version = "1"   
    yara_version = "4.2.3"   
    exemplar_hash = "5202e3fb98daa835cb807cc8ed44c356f5212649e6e1019c5481358f32b9a8a7"   
    strings:   
    $text = ".text" ascii wide   
    $itext = ".itext" ascii wide   
    $data = ".data" ascii wide   
    $rdata = ".rdata" ascii wide   
    $idata = ".idata" ascii wide   
    $xyz = ".xyz" ascii wide   
    $reloc = ".reloc" ascii wide   
    $bss = ".bss" ascii wide   
    condition:   
    #text > 2 and   
    #itext > 1 and   
    #data > 1 and   
    #rdata > 2 and   
    #idata > 3 and   
    $reloc and   
    $bss and $xyz and not   
    for any i in (0..pe.number_of_sections-1) : (   
    pe.sections[i].name == ".xyz" or   
    pe.sections[i].name == ".bss"   
    )   
   }