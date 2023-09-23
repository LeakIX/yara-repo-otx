import "pe"
rule M_Win_Hunting_CertEngine_Attestation_ProgramName_1   
   {   
    meta:   
       author = "Mandiant"   
       description = "Find driver signed via Microsoft attestation signing only with one of the identified company names of interest."    
    strings:   
       $whql_oid = {2b0601040182370a030501} //OID 1.3.6.1.4.1.311.10.3.5.1, Windows Hardware Quality Labs (WHQL) crypto -- "szOID_WHQL_CRYPTO"   
       $spc_statement_type = {2b060104018237020115} //OID 1.3.6.1.4.1.311.2.1.21, SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID   
       $spc_sp_opus_info_oid = {2b06010401823702010c} //OID 1.3.6.1.4.1.311.2.1.12, SPC_SP_OPUS_INFO_OBJID   
       $unicode1 = {59278FDE 7EB568A6 7F517EDC 79D16280 67099650 516C53F8}    
       $unicode2 = {51 69 20 4c 69 6a 75 6e}   
       $unicode3 = {4c 75 63 6b 20 42 69 67 67 65 72 20 54 65 63 68 6e 6f 6c 6f 67 79 20 43 6f 2e 2c 20 4c 74 64}   
       $unicode4 = {58 69 6e 53 69 6e 67 20 4e 65 74 77 6f 72 6b 20 53 65 72 76 69 63 65 20 43 6f 2e 2c 20 4c 74 64}   
       $unicode5 = {48 61 6e 67 7a 68 6f 75 20 53 68 75 6e 77 61 6e 67 20 54 65 63 68 6e 6f 6c 6f 67 79 20 43 6f 2e 2c 4c 74 64}   
       $unicode6 = {54 41 20 54 72 69 75 6d 70 68 2d 41 64 6c 65 72 20 47 6d 62 48}   
       $unicode7 = {798f 5dde 8d85 4eba}   
       $unicode8 = {5317 4eac 5f18 9053 957f 5174 56fd 9645 8d38 6613 6709 9650 516c 53f8}   
       $unicode9 = {798f 5efa 5965 521b 4e92 5a31 79d1 6280 6709 9650 516c 53f8}   
       $unicode10 = {53a6 95e8 6052 4fe1 5353 8d8a 7f51 7edc 79d1 6280 6709 9650 516c 53f8}   
    condition:    
       $whql_oid and   
       $spc_sp_opus_info_oid and   
       $spc_statement_type and    
       pe.signatures[0].subject == "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows Hardware Compatibility Publisher" and    
       (1 of ($unicode*))   
   }