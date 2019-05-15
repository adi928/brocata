# Brocata
Porting Suricata to Bro signatures

    $ python brocata.py
    
    payload: /(^|B0\x02\x89\x06\xFE\xC8\x89|F|04\xB0\x06\x89|F)/
    payload: /(.pdf|00|)/

By default, it is reading the included test2.txt file. Shh! Its emerging_exploits.rules in diguise. 😁