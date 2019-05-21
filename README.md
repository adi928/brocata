## Brocata
Porting Suricata to Bro signatures

    $ python brocata.py emerging-exploit.rules
    
    signature GPLEXPLOITx86Linuxmountdoverflow {
	src-port == any
	src-ip == $EXTERNAL_NET
	dst-port == 635
	dst-ip == $HOME_NET
	ip-proto == udp
	payload /(^|B0\x02\x89\x06\xFE\xC8\x89|F|04\xB0\x06\x89|F)/
	event "GPL EXPLOIT x86 Linux mountd overflow"
	}
    
    signature ETEXPLOITAdobeAcrobatReaderMaliciousURLNullByte {
	src-port == any
	src-ip == $HOME_NET
	dst-port == any
	dst-ip == $EXTERNAL_NET
	ip-proto == http
	payload /(.pdf|00|)/
	event "ET EXPLOIT Adobe Acrobat Reader Malicious URL Null Byte"
	}
    ...

Included within are the following attributes from Suricata format:
* Ports
* IP
* All the 'content' concatenated into a single payload.
* Flow keywords
* HTTP Attributes:
    * httpRequests
    * httpUri
    * http_header
    * http_client_body
    * http_request_header
    * http_reply_header
    * http_request_body
    
`sig_output` Location for all the generated signatures

## Ja3Intel.py
* Converts the suricata ruleset from abuse.ch to intel format of Bro's Intelligence framework

    ``alert tls any any -> any any (msg:"SSLBL: Malicious JA3 SSL-Client Fingerprint detected (Tofsee)"; ja3_hash; content:"906004246f3ba5e755b043c057254a29"; reference:url, sslbl.abuse.ch/ja3-fingerprints/906004246f3ba5e755b043c057254a29/; sid:906200000; rev:1;)``
    
    to
    
    ``#fields	indicator	indicator_type	meta.url
906004246f3ba5e755b043c057254a29	Intel::JA3	sslbl.abuse.ch/ja3-fingerprints/906004246f3ba5e755b043c057254a29/
`` 
