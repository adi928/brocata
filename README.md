# Brocata
Porting Suricata to Bro signatures

    $ python brocata.py emerging-exploit.rules
    
    signature custom_sig1 {
	src-port == any
	src-ip == $EXTERNAL_NET
	dst-port == 635
	dst-ip == $HOME_NET
	ip-proto == udp
	payload /(^|B0\x02\x89\x06\xFE\xC8\x89|F|04\xB0\x06\x89|F)/
	event "GPL EXPLOIT x86 Linux mountd overflow"
	}
    
    signature custom_sig2 {
	src-port == any
	src-ip == $HOME_NET
	dst-port == any
	dst-ip == $EXTERNAL_NET
	ip-proto == http
	payload /(.pdf|00|)/
	event "ET EXPLOIT Adobe Acrobat Reader Malicious URL Null Byte"
	}
    ...
