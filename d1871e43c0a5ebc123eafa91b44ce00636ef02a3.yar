rule blob_TorCommandLine {  meta:  author = "NCSC"  description = "Tor configuration file strings in blob"  date = "2023-08-31"  strings:  $ = "SocksPort 127.0.0.1:1129"  $ = "DataDirectory /data/local/prx/"  $ = "/data/local/prx/hs/"  $ = "HiddenServicePort 34371 127.0.0.1:34371"  condition:  uint32(0) == 0x464C457F and 2 of them }
