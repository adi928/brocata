import re
import argparse

sig_output = "/usr/local/bro/share/bro/site/suricata_rules/"

MapVars = {
    "external_net": "local_nets",
    "home_net": "local_nets",
    "http_servers": "http_servers",
    "http_ports": "http_ports",
    "oracle_ports": "oracle_ports",
    "smtp_servers": "smtp_servers",
    "sql_servers": "sql_servers",
    "telnet_servers": "telnet_servers",
    "aim_servers": "aim_servers",
    "shellcode_ports": "non_shellcode_ports"
}

def getConditions(line):
    conds = re.search("\(.*\)", line).group(0)
    optDict = {}
    contList = []
    i = 1

    for ele in conds.split(";"):
        eleList = ele.split(":")
        key = eleList[0].__str__().strip().replace('"', '')
        key = key.replace("(", '')
        # print("Key: " + key)
        if key == 'http-method':
            optDict[key] = 'T'
        if key == 'http_uri':
            optDict[key] = 'T'
        if key == 'http_client_body':
            optDict[key] = 'T'
        if key == 'http_header':
            optDict[key] = 'T'

        if eleList.__len__() == 2:
            value = eleList[1].__str__().strip().replace('"', '')
            if key == 'pcre':
                optDict[key] = value
            if key == 'flow':
                optDict[key] = value
            if key == 'msg':
                msg = value
            if key == 'content':
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
    return contList, msg

def getPayload(contList):
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
    return regexCond.replace("(", "\(").replace(")","\)")

def getFlow(contList):
    flowStr = "tcp-state "
    i = 1
    for options in contList:
        if options.get('flow') is not None:
            flows = options.get('flow').split(',')
            for flow in flows:
                if i != 1:
                    flowStr += ','
                if flow == 'established':
                    flowStr += flow
                if flow == 'from_server' or flow == 'to_client':
                    flowStr += "responder"
                if flow == 'to_server' or flow == 'from_client':
                    flowStr += "originator"
                i += 1
    return flowStr

def getHttpConditions(contList):
    httpRequest = ""
    uri = 1

    httpReqHeader = ""
    reqHeader = 1

    httpRepHeader = ""
    repHeader = 1

    httpReqBody = ""
    reqBody = 1

    httpString = ""

    for options in contList:
        if options.get('http_uri'):
            if uri != 1:
                httpRequest += "|"
            httpRequest += options.get('content')
            uri += 1
        if options.get('http_header') and (options.get('flow') is not None and 'to_server' in options.get('flow')):
            if reqHeader != 1:
                httpReqHeader += "|"
            httpReqHeader += options.get('content')
            reqHeader += 1
        if options.get('http_header') and (options.get('flow') is not None and 'from_server' in options.get('flow')):
            if repHeader != 1:
                httpReqHeader += "|"
            httpRepHeader += options.get('content')
            repHeader += 1
        if options.get('http_client_body'):
            if reqBody != 1:
                httpReqBody += "|"
            httpReqBody += options.get('content')
            reqBody += 1

    if httpRequest != '':
        httpString += "http-request /\(" + httpRequest + "\)/\n"
    if httpReqHeader != '':
        httpString += "http-request-header /\(" + httpReqHeader + "\)/\n"
    if httpRepHeader != '':
        httpString += "http-reply-header /\(" + httpRepHeader + "\)/\n"
    if httpReqBody != '':
        httpString += "http-request-body /\(" + httpReqBody + "\)/\n"

    return httpString


def getIP(srcIp, dstIp):
    ipStatement = ""
    if srcIp.startswith('$'):
        ipStatement += "src-ip == "+MapVars[srcIp[1:]].__str__()+"\n"
    if dstIp.startswith('$'):
        ipStatement += "dst-ip == "+MapVars[dstIp[1:]].__str__()+"\n"
    return ipStatement


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="File for Suricata rules")

    args = parser.parse_args()

    i = 1
    with open(args.file, "r") as f:
        for line in f:
            if line != '\n':
                conds, msg = getConditions(line)

                print(msg.replace(" ", '').replace("/", ''))

                sigFile = msg.replace(" ", '').replace("/", '')
                writeFile = open('rules/'+sigFile+'.sig', "w+")
                writeFile.write("signature "+sigFile+" {\n")

                attributes = line.split()
                if attributes[2].startswith('$') and attributes[5].startswith('$'):
                    writeFile.write(getIP(attributes[2].lower(), attributes[5].lower()))
                if attributes[3] == 'any':
                    writeFile.write("src-port == " + attributes[3] + '\n')
                if attributes[6] == 'any':
                    writeFile.write("dst-port == " + attributes[6]+ '\n')
                if attributes[1] == 'http' or attributes[1] == 'ftp' or attributes[1] == 'ssh':
                    writeFile.write("ip-proto == " + 'tcp' + '\n')
                else:
                    writeFile.write("ip-proto == " + attributes[1] + '\n')

                payload = getPayload(conds)
                writeFile.write("payload " + payload.replace(' ', '\\x') + '\n')

                flowStr = getFlow(conds)
                writeFile.write(flowStr + '\n')

                writeFile.write(getHttpConditions(conds))
                writeFile.write("event \""+msg+"\"" + '\n')
                writeFile.write("}\n")
                i += 1


if __name__ == "__main__":
    main()
