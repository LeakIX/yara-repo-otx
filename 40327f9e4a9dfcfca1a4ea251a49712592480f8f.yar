rule M_HUNTING_QUIETCANARY_STRINGS {   
    meta:   
    author="Mandiant"   
    strings:   
    $pdb1 = "c:\\Users\\Scott\\source\\repos\\Kapushka.Client\\BrowserTelemetry\\obj\\Release\\CmService.pdb" ascii wide nocase   
    $pdb2 = "c:\\Users\\Scott\\source\\repos\\Kapushka.Client\\BrowserTelemetry\\obj\\Release\\BrowserTelemetry.pdb" ascii wide nocase   
    $pdb3 = "c:\\Users\\Scott\\source\\repos\\BrowserTelemetry\\BrowserTelemetry\\obj\\Release\\BrowserTelemetry.pdb" ascii wide nocase   
    $orb1 = { 68 00 74 00 74 00 70 00 73 00 3A 00 2F 00 2F }   
    $orb2 = { 68 00 74 00 74 00 70 00 3A 00 2F 00 2F }   
    $command1 = "get_Command" ascii wide nocase   
    $command2 = "set_Command" ascii wide nocase   
    $command3 = "DownloadCommand" ascii wide nocase   
    $command4 = "UploadCommand" ascii wide nocase   
    $command5 = "AddCommand" ascii wide nocase   
    $command6 = "ExeCommand" ascii wide nocase   
    $command7 = "KillCommand" ascii wide nocase   
    $command8 = "ClearCommand" ascii wide nocase   
    $rc4 = {21 00 62 00 76 00 7A 00 65 00 26 00 78 00 61 00 62 00 72 00 39 00 7C 00 38 00 5B 00 3F 00 78 00 77 00 7C 00 7C 00 79 00 26 00 7A 00 6C 00 23 00 74 00 70 00   
   6B 00 7A 00 6A 00 5E 00 62 00 39 00 61 00 38 00 6A 00 5D 00 40 00 6D 00 39 00 6E 00 28 00 67 00 67 00 24 00 40 00 74 00 74 00 65 00 33 00 33 00 6E 00 28 00 32 00 72 00 7A   
   00 62 00 7A 00 69 00 74 00 75 00 31 00 2A 00 66 00 61 00 00 80 E9 4D 00 6F 00 7A 00 69 00 6C 00 6C 00 61 }   
    condition:   
    (1 of ($pdb*)) and (1 of ($orb*)) and (all of ($command*)) or ($rc4)   
   }