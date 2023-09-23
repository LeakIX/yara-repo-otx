rule Find_SVC_Ready_Like_Property_Sheets

{
        meta:
            author = "David Ledbetter"
            source = "https://twitter.com/0xToxin/status/1564289244084011014"
            description = "Rule to find extracted Document property sheets containing SVC Ready like Shellcode."
            created = "2022-08-31"

        strings:
                $Cat1 = "<cp:category>" // category property xml name
                $Comp1 = "<Company>"    // Company property xml name
                $NewNop = "6f6f6f6f6f6f6f6f6f6f6f6f6f6f"   // New Style Shellcode start
                $OldNOP = "9090909090909090909090909090"   // Old Style Shellcode Start

        condition:
                ($Cat1 and ($NewNop or $OldNOP)) or ($Comp1 and ($NewNop or $OldNOP))

}