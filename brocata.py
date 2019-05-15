import re;

def getRegex(line):
    i = 1
    optDict = {}
    contList = []
    line2 = re.search("\(.*\)", line).group(0)

    for ele in line2.split(";"):
        eleList = ele.split(":")
        key = eleList[0].__str__().strip().replace('"', '')
        # print("Key: " + key)
        if (eleList.__len__() == 2):
            value = eleList[1].__str__().strip().replace('"', '')
            # print("Value: "+value)
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
    return regexCond

def main():
    with open("test2.txt", "r") as f:
        for line in f: #line1 = f.readline()
            if (line != '\n'):
                print("payload: " + getRegex(line).replace(' ','\\x'))

if __name__ == "__main__":
    main()