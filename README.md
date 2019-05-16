# Brocata
Porting Suricata to Bro signatures

    $ python brocata.py
    
    Rule: alert udp $EXTERNAL_NET any -> $HOME_NET 635 (msg:"GPL EXPLOIT x86 Linux mountd overflow"; content:"^|B0 02 89 06 FE C8 89|F|04 B0 06 89|F"; reference:bugtraq,121; reference:cve,1999-0002; classtype:attempted-admin; sid:2100315; rev:7;)
	Payload: /(^|B0\x02\x89\x06\xFE\xC8\x89|F|04\xB0\x06\x89|F)/
	
	Rule: alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET EXPLOIT Adobe Acrobat Reader Malicious URL Null Byte"; flow: to_server,established; content:".pdf|00|"; http_uri; reference:url,idefense.com/application/poi/display?id=126&type=vulnerabilities; reference:url,www.securiteam.com/windowsntfocus/5BP0D20DPW.html; reference:cve,2004-0629; reference:url,doc.emergingthreats.net/bin/view/Main/2001217; classtype:attempted-admin; sid:2001217; rev:11;)
	Payload: /(.pdf|00|)/

By default, it is reading the included test2.txt file. Shh! Its emerging_exploits.rules in diguise. 😁
