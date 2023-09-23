rule BitRATStringBased
{
    meta:
        author = "KrabsOnSecurity"
        date = "2020-8-22"
        description = "String-based rule for detecting BitRAT malware payload"
    strings:
        $tinynuke_paste1 = "TaskbarGlomLevel"
        $tinynuke_paste2 = "profiles.ini"
        $tinynuke_paste3 = "RtlCreateUserThread"
        $tinynuke_paste4 = "127.0.0.1"
        $tinynuke_paste5 = "Shell_TrayWnd"
        $tinynuke_paste6 = "cmd.exe /c start "
        $tinynuke_paste7 = "nss3.dll"
        $tinynuke_paste8 = "IsRelative="
        $tinynuke_paste9 = "-no-remote -profile "
        $tinynuke_paste10 = "AVE_MARIA"
        
        $commandline1 = "-prs" wide
        $commandline2 = "-wdkill" wide
        $commandline3 = "-uac" wide
        $commandline4 = "-fwa" wide
    condition:
        (8 of ($tinynuke_paste*)) and (3 of ($commandline*))
}