rule M_Hunting_Win_ConventionEngine_PDB_Attestation_Multiple_1   
   {   
    meta:   
       author = "Mandiant"   
       description = "Looking for PDB path strings that has been observed in malicious samples which were attestation signed"   
    strings:   
       $anchor = "RSDS"   
       $pdb1 = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\.{0,250}gamehacks.{0,250}boot_driver.{0,250}\.pdb\x00/ nocase   
       $pdb2 = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\.{0,250}MyDriver1.{0,250}wfp_vpn.{0,250}\.pdb\x00/ nocase   
       $pdb3 = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\.{0,250}FilDriverx64_win10.{0,250}\.pdb\x00/ nocase   
       $pdb4 = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\.{0,250}RedDriver_win10.{0,250}\.pdb\x00/ nocase   
       $pdb5 = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\.{0,250}sellcode.{0,250}MyDriver.{0,250}\.pdb\x00/ nocase   
       $pdb6 = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\.{0,250}Users\\ljl11{0,250}\.pdb\x00/ nocase   
       $pdb7 = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\.{0,250}RkDriver64.{0,250}MyDriver1.{0,250}\.pdb\x00/ nocase   
       $pdb8 = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\.{0,250}\\ApcHelper.{0,250}TSComputerManager.{0,250}\.pdb\x00/ nocase   
    condition:   
       (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and filesize < 20MB and $anchor and (1 of ($pdb*))   
   }