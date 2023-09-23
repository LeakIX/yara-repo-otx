import "pe"
rule M_Hunting_Signed_Driver_Attestation_1   
   {   
    meta:   
    author = "Mandiant"   
    date_created = "2022-10-20"   
    description = "Find driver signed via Microsoft attestation signing only (no EV certificate signing outside of Microsoft Windows Hardware Compatibility Publisher)" //https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation   
    strings:   
    $whql_oid = {2b0601040182370a030501} //OID 1.3.6.1.4.1.311.10.3.5.1, Windows Hardware Quality Labs (WHQL) crypto -- "szOID_WHQL_CRYPTO"   
    $spc_statement_type = {2b060104018237020115} //OID 1.3.6.1.4.1.311.2.1.21, SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID   
    $spc_sp_opus_info_oid = {2b06010401823702010c} //OID 1.3.6.1.4.1.311.2.1.12, SPC_SP_OPUS_INFO_OBJID   
    condition:   
    pe.signatures[0].subject == "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows Hardware Compatibility Publisher" and   
    $whql_oid and   
    $spc_sp_opus_info_oid and   
    $spc_statement_type   
   }