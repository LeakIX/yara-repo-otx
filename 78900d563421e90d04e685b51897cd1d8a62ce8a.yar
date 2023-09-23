rule Zeppelin_14 {   
      meta:   
         description = "Zeppelin - from files 7430d1dbf96b83426cfb859b8cdb2633489d08de8782c162de6c631978c61dea, c3c1546d6f3b48eabcab82390b5628a2dd438b82989969dd1c1016c8f7366911"   
         author = "yarGen Rule Generator"   
         reference = "https://github.com/Neo23x0/yarGen"   
         date = "2022-08-08"   
         hash1 = "7430d1dbf96b83426cfb859b8cdb2633489d08de8782c162de6c631978c61dea"   
         hash2 = "c3c1546d6f3b48eabcab82390b5628a2dd438b82989969dd1c1016c8f7366911"   
      strings:   
         $s1 = "5QjNk03HyzM2et9qHr8ZTHougWPSFyxuTF0qxEsTWH9lWO2qmZd1dDNYE1wxQzBrEBagnNBk8o7NSlOoBnAtwLiV8nt8M58t7OdbDRRSMw2YvdGL6z4k+VK1/9yNXZNG" ascii   
         $s2 = "9rcTzUSkqWgdnfIVTX2J1CoPyg3+LS5R0jK4R0QkO6hcJpNQyNZqHrMmDajol+GWoEFi5TskdZD9EZSvuDfQzqmX+PiEDpFIVXaqK7gCdU5nsdmjlr1VSyXDYQHCEK9/" ascii   
         $s3 = "bYmmMqb1Kdl+D9v+iTxmSfgk6HQknFP8InWpvAnZh4/RuYgX5ndmosfJruD2Ln3kLElx1cga4fSQXmfc0hIILQK9KLSp64KfbtnV9RuaCDo3ZzwNgOPZructcKqozH9p" ascii   
         $s4 = "bs73QFYm9f4XP+ALKKpAqPgFNhg5v2qR/XKSpQ1S92rpFsYWaTe3SG/6HNIIFC/z+SF9JRzFxV4s7rd59X4vfP4ruhL1ybXHZyotxBeDM7T5Mz8x1N+nvhsIW2yvCgDn" ascii   
         $s5 = "IUeoKEkBZiCBGOZD3/eoVSW2XRLAM01hbuZB2rPV8U8jho83FDQJBmLhL8A8UF7hJquMibKt5WwlOYMagbW/xmmLCglENsiHVC1yuicGVJ3MTOcvz5RWnzVvps5/GEUN" ascii   
         $s6 = "pg8le4yoQ80a8hZ0kw4eaD0EA210GFN4boHgSZW1PFQoaWvHtSSXudyUj8MY+V9+G1dNnov0C6P7mv/JVDmV9jAr3tzThfrkipNYHVfp3MTVVRce06BaLoUpWs6gnWKM" ascii   
         $s7 = "0ffldkDRAq50EKe6WVxy5ZjbAOUcToLg27iB15texcRDiU9fzwvAn+pwRQflCDlNqgsuHD5EGBh8BwwrMdtrMfPMYP7FooiA3yqJrYCscIY7xa5KosRfBHFRcKGXsm9o" ascii   
         $s8 = "HIL8CifFBXDbhqXGFugjZ/BDqHkzn2RSjOIJPHGoiI3SqKZ/d0kd5l5peCp8udEHGTldXuNx6fMZK/Vkghnnyi9eUTwkHZ1c2V65TsGGewkkbAPpAMLBifamNhlsgN+5" ascii   
         $s9 = "Og3GkgGQaQv85FAEBFAoh+hpVAWWKgSQtewGaWSlRIBSAftsU0ISTECgZu+rRRfRksgVeiBu7Yg9TBSyL8dfyYEyTJ5zq9zKc08xVkKso2lN/fUrrFHyCyVL9UL/dsay" ascii   
         $s10 = "ptd8vN2uubsBEj1RedKSMXNSBwnc/Nk6NAvzLov5MP51/SdUUE+1TMEx9KvDbovxYI5QYq0Fuut+RjGpSpAWMl5FWTMDAbsQ4A7MHvmoB5T73ElnvpPUXqR0y/V5qAQG" ascii   
         $s11 = "AGP8HroUQyhBF87ioIeX7rJdqvvd4YHy1kbOQXSqFqqlm0WpW34M/xG5IyJ6tiB0KSV11JSNgijQnBi3Ed3PHCJLzan+cLhXaXQ0w68Ist8EO+los6QlDNDzFn62k9ht" ascii   
         $s12 = "21K8jhHaED9mVbDNRuirDxORoYqNjNNxnlL45jRFM/d7ZkOg9AIHZjj/DRbuCUfoUanmsFFYNd4fBYRQke6If5bbG+fngGD3aLhIn003YIIkbWLTlUqNlBRx6wMoX9zh" ascii   
         $s13 = "2w+58UeK+kRC5GJQtsT6ZO7AeDdCKu5u+ywu3/sJg32arC5G/eLA7oOWHqTy7fusPjLIeJjNFSIXch80/EXqZNr1pk7vZ17M8Okt/Lv8RhKrNeRMHiqC7BfVB++kApO+" ascii   
         $s14 = "ptd8vN2uubsBEj1RedKSMXNSBwnc/Nk6NAvzLov5MP51/SdUUE+1TMEx9KvDbovxYI5QYq0Fuut+RjGpSpAWMl5FWTMDAbsQ4A7MHvmoB5T73ElnvpPUXqR0y/V5qAQG" ascii   
         $s15 = "Vdxy9DPHwpxpkmw7IznbRSqy9WuZFMSZ+skFt8D0KSxPATWBhoY/c1SiRlVyLG8zV8ftR94ynrzjQ4OBNjZ6G3yc/3XXK4PpHohaXC2b/+spHlGp56hrDkxCiu+H31PU" ascii   
         $s16 = "4YnPPVrgrig+Pig1bxYK7Q2ik7uo607NCaicQJelXefmYp3qzm0BzCGV7axJVy2Htaz7ZxBn8MF3gMuOBi9s+iSvO9Gbz0STA0y1tjzHYuXzkCSZj7Jef67WhOosyN2u" ascii   
         $s17 = "Uf/Ncyp3FgdjNWSmF908WB1iFaG7BarRv7ZVaVLXKzMXbysc0pCZoRPM0LIUPJubPvvLK9C8N6dCof7Isb6BA3l9TP7OS0n0LGT6msAdn0pqsGU0ifFLkwvNXas1yCaV" ascii   
         $s18 = "Uf/Ncyp3FgdjNWSmF908WB1iFaG7BarRv7ZVaVLXKzMXbysc0pCZoRPM0LIUPJubPvvLK9C8N6dCof7Isb6BA3l9TP7OS0n0LGT6msAdn0pqsGU0ifFLkwvNXas1yCaV" ascii   
         $s19 = "UEXhah/L" fullword ascii   
         $s20 = "0Q8icB1REGRiI7cpCT1QDUQ=" fullword ascii   
      condition:   
         ( uint16(0) == 0x5a4d and filesize < 800KB and ( 8 of them )   
         ) or ( all of them )   
   }