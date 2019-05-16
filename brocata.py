import re
import argparse

def getPayload(line):
    i = 1
    optDict = {}
    contList = []
    line2 = re.search("\(.*\)", line).group(0)
    msg = ""

    for ele in line2.split(";"):
        eleList = ele.split(":")
        key = eleList[0].__str__().strip().replace('"', '')
        key = key.replace("(",'')
        # print("Key: " + key)
        if (eleList.__len__() == 2):
            value = eleList[1].__str__().strip().replace('"', '')
            # print("Value: "+value)
            if key == 'msg':
                msg = value;
            if (key == 'content'):
                contList.insert(i, optDict)
                optDict = {
                    "optionId": i
                }
                i += 1
                optDict[key] = value
            if (key == 'depth'):
                optDict[key] = value
            if (key == 'offset'):
                optDict[key] = value
            if (key == 'distance'):
                optDict[key] = value
            if (key == 'within'):
                optDict[key] = value
    contList.insert(i, optDict)
    regexCond = "/"
    for options in contList:
        if (options.get('offset') is not None):
            regexCond = ".{" + options.get('offset') + "}"
        if (options.get('distance') is not None):
            regexCond += ".{" + options.get('distance') + "}"
        if (options.get('content') is not None):
            regexCond += "(" + options.get('content') + ")"
        if (options.get('within') is not None):
            within = int(options.get('within')) / 8
            if (within >= 1):
                regexCond += "{" + int(within).__str__() + "}"
    regexCond += "/"
    return regexCond.replace("(", "\(").replace(")","\)"), msg

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="File for Suricata rules")

    args = parser.parse_args()

    i = 1
    with open(args.file, "r") as f:
        for line in f:
            if (line != '\n'):
                attributes = line.split()
                payload, msg = getPayload(line)
                sigFile = msg.replace(" ", '')
                writeFile = open(msg.replace(" ", ''), "w+")
                writeFile.write("signature "+sigFile+" {\n")
                if attributes[3] != 'any':
                    writeFile.write("src-port == " + attributes[3] + '\n')
                #writeFile.write("src-ip == " + attributes[2] + '\n')
                if attributes[6] != 'any':
                    writeFile.write("dst-port == " + attributes[6]+ '\n')
                #writeFile.write("dst-ip == " + attributes[5] + '\n')
                if (attributes[1] == 'http' or attributes[1] == 'ftp' or attributes[1] == 'ssh'):
                    writeFile.write("ip-proto == " + 'tcp' + '\n')
                else:
                    writeFile.write("ip-proto == " + attributes[1] + '\n')
                writeFile.write("payload " + payload.replace(' ', '\\x') + '\n')
                writeFile.write("event \""+msg+"\"" +'\n')
                writeFile.write("}\n")
                i += 1

if __name__ == "__main__":
    main()