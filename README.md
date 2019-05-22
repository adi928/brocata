## Brocata
Porting Suricata to Bro signatures

    $ python brocata.py emerging-exploit.rules
    
    signature NCCGROUPRDPconnectionsetupwithMS_T120channelpotentialCVE-2019-0708 {
    src-ip == any
    dst-ip == any
    src-port == any
    dst-port == 3389
    ip-proto == tcp
    payload /(\x{03}\x{00}).{2}(?:\w){0,2}?(\x{02}\x{f0})(?:\w){0,512}?(\x{00}\x{05}\x{00}\x{14}\x{7c}\x{00}\x{01}).{3}(?:\w){0,384}?(\x{03}\x{c0}).{6}(?:\w){0,372}?(MS_T120\x{00})/
    tcp-state originator,established
    event "NCCGROUPRDPconnectionsetupwithMS_T120channelpotentialCVE-2019-0708"
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
