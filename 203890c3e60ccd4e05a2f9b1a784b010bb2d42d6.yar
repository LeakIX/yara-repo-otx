rule netd_TorDomainPath {  meta:  author = "NCSC"  description = "Tor hostname path string found in netd"  date = "2023-08-31"  strings:  $ = "/data/local/prx/hs/hostname"  condition:  uint32(0) == 0x464C457F and any of them }
