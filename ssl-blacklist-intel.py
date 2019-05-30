#!/usr/bin/env python3

import sys

import requests

sslURL = 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv'
sslBlocklistCSV = 'sslblicklist.csv'
sslBlocklistDAT = 'sslBlocklist.dat'

ransomwareUrl = 'https://ransomwaretracker.abuse.ch/feeds/csv/'
ransomewareCSV = 'ransomewaretracker.csv'
ransomewareDAT = 'ransomewaretracker.dat'

def main():
    # Download the ssl blocklist feeds
    try:
        r = requests.get(sslURL, allow_redirects=True)
    except requests.HTTPError as err:
        print("An HTTP error occured:\n" + err)
        sys.exit()
    except requests.Timeout as err:
        print("The request timed out.\n" + err)
        sys.exit()
    except requests.RequestException as err:
        print("The request had something really bad with it. Bailing now...\n" + err)
        sys.exit()
    except requests.ConnectionError as err:
        print("The connection has not been established and disconnected with an error\n" + err)
        sys.exit()
    except requests.SSLError as err:
        print("The connection has SSL error\n" + err)
        sys.exit()

    open(sslBlocklistCSV, 'wb').write(r.content)

    with open(sslBlocklistCSV, newline='', encoding='ISO-8859-1') as cvsfile:
        lineCount = 0
        writeFile = open(sslBlocklistDAT, 'w+')
        for line in cvsfile:
            if line.startswith('# Listing') or lineCount >= 1:
                row = line.replace('#','').replace('"', '')
                sslComp = row.split(',')
                if sslComp.__len__() <= 1:
                    continue
                if lineCount == 0:
                    writeFile.write('#fields\tindicator\tindicator_type\tmeta.url\tmeta.source\n')
                    lineCount += 1
                else:
                    writeFile.write(sslComp[1] + '\tIntel::FILE_HASH' + '\thttps://sslbl.abuse.ch/ssl-certificates/sha1/'\
                                    + sslComp[1] + '\tabuse.ch\n')
                    lineCount += 1

    # Download the ransomware blocklist feeds
    try:
        r = requests.get(ransomwareUrl, allow_redirects=True)
    except requests.HTTPError as err:
        print("An HTTP error occured:\n" + err)
        sys.exit()
    except requests.Timeout as err:
        print("The request timed out.\n" + err)
        sys.exit()
    except requests.RequestException as err:
        print("The request had something really bad with it. Bailing now...\n" + err)
        sys.exit()
    except requests.ConnectionError as err:
        print("The connection has not been established and disconnected with an error\n" + err)
        sys.exit()
    except requests.SSLError as err:
        print("The connection has SSL error\n" + err)
        sys.exit()

    open(ransomewareCSV, 'wb').write(r.content)

    with open(ransomewareCSV, newline='', encoding='ISO-8859-1') as csvfile:
        lineCount = 0
        writeFile = open(ransomewareDAT, 'w+')
        for line in csvfile:
            if line.startswith('# Firstseen') or lineCount >= 1:
                line = line.replace('#','').replace('"', '')
                components = line.split(',')
                if components.__len__() <= 1:
                    continue
                if lineCount == 0:
                    writeFile.write('#fields\tindicator\tindicator_type\tmeta.url\tmeta.source\n')
                    lineCount += 1
                else:
                    domain = ''
                    if components[3] == components[7]:
                        ips = components[7].split('|')
                    else:
                        domain = components[3]

                    url = components[4]

                    for ip in ips:
                        ipIntelStr = ip + '\tIntel::ADDR' + '\thttps://ransomwaretracker.abuse.ch/feeds/' + '\t' \
                                     + components[1]+'-'+components[2]+components[6]+'-'+components[8]+'-'+components[9]
                        writeFile.write(ipIntelStr)

                    if domain != '':
                        domainIntelStr = domain + '\tIntel::DOMAIN' + '\thttps://ransomwaretracker.abuse.ch/feeds/' + '\t' \
                                     + components[1] + '-' + components[2] + components[6] + '-' + components[8] + '-' + \
                                     components[9]
                        writeFile.write(domainIntelStr)

                    if url != '':
                        urlIntelStr = url + '\tIntel::URL' + '\thttps://ransomwaretracker.abuse.ch/feeds/' + '\t' \
                                     + components[1] + '-' + components[2] + components[6] + '-' + components[8] + '-' + \
                                     components[9]
                        writeFile.write(urlIntelStr)
                    lineCount += 1
        writeFile.close()


if __name__ == '__main__':
    main()