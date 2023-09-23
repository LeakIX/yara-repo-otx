rule CodeRAT { meta: source = "SafeBreach.com" date = "2022-08-23" description = "Detects CodeRAT binary" strings: $interesting_string0 = "2A47E576EB06CA284E7B3D92A0412923" $interesting_string1 = "httpdebugger.com" $interesting_string2 = "wordbetraied" $interesting_string3 = "Newtonsoft.Json.dll" $interesting_string4 = "working.docx" $interesting_string5 = "wifipasswords" $interesting_string6 = "pass.txt" $interesting_string7 = "boss.txt" $interesting_string8 = "command.txt" condition: all of ($interesting_*) }