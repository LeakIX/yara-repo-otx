rule deadbolt_cgi_ransomnote : ransomware {
    meta:
        description = "Looks for CGI shell scripts created by DeadBolt"
        author = "Trend Micro Research"
        date = "2022-03-25"
        hash = "4f0063bbe2e6ac096cb694a986f4369156596f0d0f63cbb5127e540feca33f68"
        hash = "81f8d58931c4ecf7f0d1b02ed3f9ad0a57a0c88fb959c3c18c147b209d352ff1"
        hash = "3058863a5a169054933f49d8fe890aa80e134f0febc912f80fc0f94578ae1bcb"
        hash = "e0580f6642e93f9c476e7324d17d2f99a6989e62e67ae140f7c294056c55ad27"

    strings:
        $= "ACTION=$(get_value \"$DATA\" \"action\")"
        $= "invalid key len"
        $= "correct master key"
        $= "'{\"status\":\"finished\"}'"
        $= "base64 -d 2>/dev/null"

    condition:
        uint32be(0) != 0x7F454C46 // We are not interested on ELF files here
        and all of them
}
