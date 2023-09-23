rule Zeppelin_17 {
   meta:
      description = "Zeppelin - from files 4a4be110d587421ad50d2b1a38b108fa05f314631066a2e96a1c85cc05814080, faa79c796c27b11c4f007023e50509662eac4bca99a71b26a9122c260abfb3c6, 9ef90ec912543cc24e18e73299296f14cb2c931a5d633d4c097efa372ae59846, 307877881957a297e41d75c84e9a965f1cd07ac9d026314dcaff55c4da23d03e, e48cf17caffc40815efb907e522475722f059990afc19ac516592231a783e878"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-08-08"
      hash1 = "4a4be110d587421ad50d2b1a38b108fa05f314631066a2e96a1c85cc05814080"
      hash2 = "faa79c796c27b11c4f007023e50509662eac4bca99a71b26a9122c260abfb3c6"
      hash3 = "9ef90ec912543cc24e18e73299296f14cb2c931a5d633d4c097efa372ae59846"
      hash4 = "307877881957a297e41d75c84e9a965f1cd07ac9d026314dcaff55c4da23d03e"
      hash5 = "e48cf17caffc40815efb907e522475722f059990afc19ac516592231a783e878"
   strings:
      $s1 = "r0BJ5G8ZCEaFzvyLdnfq+g4ANDxaUaBF6UunJ+VIl6ogA3y+mUYNMo7Y0cuL429kMP9wallogHah/X2n5GYeBS/IyswdttYPOYNewDO7Bt5WOQO3K8tjE5XWV+QwtsNr" ascii
      $s2 = "r0BJ5G8ZCEaFzvyLdnfq+g4ANDxaUaBF6UunJ+VIl6ogA3y+mUYNMo7Y0cuL429kMP9wallogHah/X2n5GYeBS/IyswdttYPOYNewDO7Bt5WOQO3K8tjE5XWV+QwtsNr" ascii
      $s3 = "P5hFWBZuz9iPOcK7YRlFly6FJx7ioyFwqiJR9x2dZBkRMwUVpWmuG3PMPNRtqncNW96/GG6Zw2wX8byOE3q6Kr2dBtAVvDwKn1rJNP8VkqVNh2e0Vnwxdn8wYmpuMINw" ascii
      $s4 = "ZXFjL5I/XLuVOZoW10sUQ8Qwxzrodf45iJ0PvviyZNrHT5glpiUX4WIZ5w/1O8cgWOMZQLrAf+WTV7YE8vLD/zF1g+JeRb9LnAnT6x0gsWFh3y5A7zFXSfnvYaIGqTdI" ascii
      $s5 = "Um+dOulCgcUUNpM3XGRs5XR7m1/fUslO+aniokZq68ydCfJ3rv9euFqqIDnwu+y+iRHgD6i9aBnTwioWBx+8TXEYJj+Wj+NJIwyutpsbgGQjtlz1aDT4n5rwCfCq04El" ascii
      $s6 = "72woqMgistNxWyKlQBa6KLyHqkaJQ5lzpoasscsXS4MIoOJvFaSaNFXntedlwyOtOimE9PR1iP2UWMyNo/6XdBzpDtwc909R4opBfkF3z+wzZTHEcFauPhi9a7va3wp9" ascii
      $s7 = "ZgYs3lTOet10NkSUUA+mGZJLai5YTywBu+EE+F8BnfNqpQgefbMA7d0CTlQtD/xjvQuQNhvDO4HXgo6H/nMjEdCV43xTiNm/lGkIpLMZ5+m/BjFI34j9NL+cFhuCTF+k" ascii
      $s8 = "uL0Y+nDdyvprRRKWkmNwuXzlDL4V5l1dW4gtTsNdGrjjy5ey9UXIRbYL/f8F3sGY6FkpFk9UrkYx0a/+JXBX/PNrQDKIjxEVPCgGWNk7Nb6FQrFL7adWGgKCX6srIzkt" ascii
      $s9 = "QusLdCRf+UgZso1uJNmMEbLqv+kL4Tb0Q742L946g4S/WB+vMLLJwVAVs4Clc4e6+AIwYKUOpn1zF9nGwE9+ISseQhg/dyJUxJdFHD7eGTTQNpja01tFna9zlM5ALB8v" ascii
      $s10 = "yi1OnhhYgThMOhD0unrmj1oki7c9jXt1nQBLRn3NgjTrCs3oEyXY+IlICjFi/+wgD/6vB9X61MihWT7LTnWlxXSadWqWG0v7AgX9ejz1kp+biEnZRhdfAv1ABPncD/aQ" ascii
      $s11 = "cTUUkjNEx8QtHyObKu5UJ9x1ki/5EQU8WQh0gUjx7k7RBB0wkMlYmgSRD2W8yncNkKT9GILvwxIIKKGe5nBssW0NH9nVC5PmawwZUyAu2zWkmhI6qjA9+bxbxRR0kXza" ascii
      $s12 = "YhrTbx/4+FQmOftILtcJEs3joheCe1eKvmP1WfGpdr4cS40TWQEpQOVHq+SDoE/R3GL1hjOvB3ghwUqgHHpFnZPpwmEBmVDBnx/vGTgcthxIsc4aPpm+4A+5gvpqJXVw" ascii
      $s13 = "feqVLvoVAMx6sKTyCyiIoyi2yx92O1UF6X5tGYdY55YWUUE5pQHQ8Bms0teFYwuPkw1zpac5GQP8BNn+qYnrgabc6O+/GHz4f5jWCPp7VNRQBKE1ryas4wr5dpBBcwyR" ascii
      $s14 = "0bpx4/QyrbJdwAiZB8kiTowuyIpH7PPB1zjazKpLoLBv2dzFmhKrbc5NNh32iSBmf5ffHPBj+9QUbWjaryFPg49DTXPCrf99llJp/4XdiJcBwFdcdwcuAKbQA3inBU19" ascii
      $s15 = "wqBA5M3TokuN3RFSUb7PkgMYrrfBkpORgEoTjpZ2dCEZay59EmE63mDAdlEsk2f8tMlt88jdXSAik+y1kYoJi9J6fnV896GiuBoNGhQDL8cbxJ4xcJa3D1ptskGXEaKa" ascii
      $s16 = "5R\":t:\\" fullword ascii
      $s17 = "VDb2ITEpnTCJwDMKPAodbCfUJn6vePDXaYxvf9LAIOPv6EffcP1Y/Gn60NU/DAUV8NPUy6dDHfa5iUgrgCLJEFd2b90A3nkWBwCAPWAl+LKkmASGfR2TTKIk9dihMrE+" ascii
      $s18 = "ODfxx6dwC0jNJretV12YWIcaKRUwOE5sUg5P2X3wPGUi4T0CzqqZLrAe+Ly970tXpoW1jIOpeV+Dl5AtcT2Gd6R9iqL68WsoD/NPD5hZLduLg3WXhEuDrmQtf1IwXqEr" ascii
      $s19 = "ODfxx6dwC0jNJretV12YWIcaKRUwOE5sUg5P2X3wPGUi4T0CzqqZLrAe+Ly970tXpoW1jIOpeV+Dl5AtcT2Gd6R9iqL68WsoD/NPD5hZLduLg3WXhEuDrmQtf1IwXqEr" ascii
      $s20 = "yIc8f+iuP6jvlL8k0CDwMQ==" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and ( 8 of them )
      ) or ( all of them )
}