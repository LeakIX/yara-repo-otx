/*
    Although this web shell has been around for a minute, I could not 
    find any good rules for detection. Enjoy!
    Published 2022-10-13
*/
rule php_alfa_team
{
    meta:
        author      = "Michael Taggart https://github.com/mednet-mtaggart"
        date        = "2022/10/13"
        description = "Detects ALFA TEAM's web shell"
    strings:
        $a = "<?php"
        $b = "set_time_limit(0)"
        $c = "'fun'.'ct'.'i'.'o'.'n_exi'.'s'.'ts'"
        $d = "'e'.'v'.'a'.'l'"
        $e = "'gzin'.'f'.'l'.'a'.'te'"
    condition:
        all of them
}