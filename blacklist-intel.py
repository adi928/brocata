import io
import sys
import requests
import os

sslURL = 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv'
sslBlocklistCSV = 'sslBlocklist.csv'
sslBlocklistDAT = 'sslBlocklist.dat'

ja3URL = 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv'
ja3CSV = 'ja3Blocklist.csv'
ja3DAT = 'ja3Blocklist.dat'

ransomwareURL = 'https://ransomwaretracker.abuse.ch/feeds/csv/'
ransomewareCSV = 'ransomewaretracker.csv'
ransomewareDAT = 'ransomewaretracker.dat'

def sslBlockList():
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

    cvsfile = io.open(sslBlocklistCSV, 'r', encoding='ISO-8859-1')
    lineCount = 0
    writeFile = open(sslBlocklistDAT, 'w+')
    for line in cvsfile:
        if line.startswith('# Listing') or lineCount >= 1:
            row = line.replace('#', '').replace('"', '')
            sslComp = row.split(',')
            if sslComp.__len__() <= 1:
                continue
            if lineCount == 0:
                writeFile.write('#fields\tindicator\tindicator_type\tmeta.url\tmeta.source\n')
                lineCount += 1
            else:
                writeFile.write(
                    sslComp[1] + '\tIntel::FILE_HASH' + '\thttps://sslbl.abuse.ch/ssl-certificates/sha1/' \
                    + sslComp[1] + '\tabuse.ch\n')
                lineCount += 1


def ja3Fingerprint():
    # Download the JA3 blocklist feeds
    try:
        r = requests.get(ja3URL, allow_redirects=True)
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

    open(ja3CSV, 'wb').write(r.content)

    cvsfile = io.open(ja3CSV, 'r', encoding='ISO-8859-1')
    lineCount = 0
    ja3writeFile = open(ja3DAT, 'w+')
    for line in cvsfile:
        if line.startswith('# ja3') or lineCount >= 1:
            row = line.replace('#', '').replace('"', '')
            ja3Comp = row.split(',')
            if ja3Comp.__len__() <= 1:
                continue
            if lineCount == 0:
                ja3writeFile.write('#fields\tindicator\tindicator_type\tmeta.url\tmeta.source\n')
                lineCount += 1
            else:
                ja3writeFile.write(
                    ja3Comp[0] + '\tIntel::JA3' + '\thttps://sslbl.abuse.ch/ja3-fingerprints/' \
                    + ja3Comp[0] + '\tabuse.ch\n')
                lineCount += 1
    ja3writeFile.close()


def ransomewareBlocklist():
    # Download the ransomware blocklist feeds
    try:
        r = requests.get(ransomwareURL, allow_redirects=True)
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

    csvfile = io.open(ransomewareCSV, 'r', encoding='ISO-8859-1')
    lineCount = 0
    rwWriteFile = open(ransomewareDAT, 'w+')
    for line in csvfile:
        if line.startswith('# Firstseen') or lineCount >= 1:
            line = line.replace('#', '').replace('"', '')
            components = line.split(',')
            if components.__len__() <= 1:
                continue
            if lineCount == 0:
                rwWriteFile.write('#fields\tindicator\tindicator_type\tmeta.url\tmeta.source\n')
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
                                 + components[1] + '-' + components[2] + components[6] + '-' + components[8] + '-' + \
                                 components[9]
                    rwWriteFile.write(ipIntelStr)

                if domain != '':
                    domainIntelStr = domain + '\tIntel::DOMAIN' + '\thttps://ransomwaretracker.abuse.ch/feeds/' + '\t' \
                                     + components[1] + '-' + components[2] + components[6] + '-' + components[
                                         8] + '-' + \
                                     components[9]
                    rwWriteFile.write(domainIntelStr)

                if url != '':
                    urlIntelStr = url + '\tIntel::URL' + '\thttps://ransomwaretracker.abuse.ch/feeds/' + '\t' \
                                  + components[1] + '-' + components[2] + components[6] + '-' + components[
                                      8] + '-' + \
                                  components[9]
                    rwWriteFile.write(urlIntelStr)
                lineCount += 1
    rwWriteFile.close()

def main():
    os.system('python --version')
    # Convert the ssl blocklist feeds
    sslBlockList()
    # Convert the ja3 blocklist feeds
    ja3Fingerprint()
    # Convert the ransomeware blocklist feeds
    ransomewareBlocklist()

if __name__ == '__main__':
    main()