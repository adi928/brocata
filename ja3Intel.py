import argparse
import re


def disassemble(line):
    conditions = re.search("\(.*\)", line).group(0).replace(" ", '')
    attributesList = conditions.split(";")
    optDicts = {}
    for atts in attributesList:
        if atts == "ja3_hash":
            optDicts[atts] = 'true'
        if atts.startswith('content') and optDicts['ja3_hash'] is not None and optDicts['ja3_hash'] == 'true':
            cntTemp = atts.split(':')
            keyContent = cntTemp[0]
            content = cntTemp[1].replace('"','')
        if atts.startswith('reference'):
            tempUrl = atts.split(',')
            url = tempUrl[1]
    return content,url


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="File for Suricata rules")

    args = parser.parse_args()

    writeFile = open('intel/ja3.intel', "w+")
    writeFile.write('#fields\tindicator\tindicator_type\tmeta.url\n')
    with open(args.file, "r") as f:
        for line in f:
            if line.startswith('alert') and line.__contains__('ja3_hash'):
                fingerprint, url = disassemble(line)
                writeFile.write(fingerprint + "\tIntel::JA3\t" + url +"\n")


if __name__ == '__main__':
    main()