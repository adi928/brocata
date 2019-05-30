## Brocata
Porting Suricata to Bro signatures

Update: The script has been completely automated from end-to-end which means,
it doesn't need an argument anymore. It downloads the blacklists, rules from the provided 
urls, giving appropriate error messages if the link is buggy.

In this example it is converting CVE 2019-0708 rule

    $ python brocata.py
    
    signature cve-2019-0708 {
        src-ip == any
        dst-ip == any
        src-port == any
        dst-port == 3389
        ip-proto == tcp
        payload /(\x{03}\x{00}).{2}(?:\w){0,2}?(\x{02}\x{f0})(?:\w){0,512}?(\x{00}\x{05}\x{00}\x{14}\x{7c}\x{00}\x{01}).{3}(?:\w){0,384}?(\x{03}\x{c0}).{6}(?:\w){0,372}?(MS_T120\x{00})/
        tcp-state originator,established
        event "NCCGROUP RDP connection setup with MS_T120 channel potential CVE-2019-0708"
    }

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

Update: The generated signatures are now stored within a single file within the 
bro site folder (`$Prefix/bro/share/bro/site/`) within the folder name `suricata_rules`.

The script also generates the __load__.bro within the same folder.

The only thing user needs to manually do is add `@load suricata_rules` in local.bro where Bro site is.

## blacklist-intel.py
* Converts the SSL, JA3 fingerprints and Ransomeware data from CSV, obtained from abuse.ch 
to intel files which can be used in Intel framework of Bro IDS.