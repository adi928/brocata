import argparse
import csv


def main():
    with open('sslblacklist.csv', newline='') as cvsfile:
        sslBlacklist = csv.reader(cvsfile, delimiter=',')
        lineCount = 0
        writeFile = open('intel/sslIntel.dat', 'w+')
        for row in sslBlacklist:
            if lineCount == 0:
                writeFile.write('#fields\tindicator\tindicator_type\tmeta.url\tmeta.source\n')
                lineCount += 1
            else:
                writeFile.write(row[1] + '\tIntel::FILE_HASH' + '\thttps://sslbl.abuse.ch/ssl-certificates/sha1/'+row[1]+'\t' + row[2] +'\n')
                lineCount += 1


if __name__ == '__main__':
    main()