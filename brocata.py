import re
import os
import sys

import requests

sig_output = "/usr/local/bro/share/bro/site/suricata_rules/"
loadBro = '__load__.bro'
url = 'https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz'
downloadedRules = 'emerging-exploit.tar'

MapVars = {
    "home_net": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"
}


def getConditions(line):
    conds = re.search("\(.*\)", line).group(0)
    optDict = {}
    contList = []
    i = 1
    msg = ""

    for ele in conds.split(";"):
        eleList = ele.split(":")
        key = eleList[0].__str__().strip().replace('"', '')
        key = key.replace("(", '')
        if key == 'http-method':
            optDict[key] = 'T'
        if key == 'http_uri':
            optDict[key] = 'T'
        if key == 'http_client_body':
            optDict[key] = 'T'
        if key == 'http_header':
            optDict[key] = 'T'

        if eleList.__len__() >= 2:
            value = eleList[1].__str__().strip().replace('"', '')

            if key == 'isdataat':
                optDict[key] = value
            if key == 'flow':
                optDict[key] = value
            if key == 'msg':
                for opts in eleList[1:]:
                    msg += opts
            if key == 'content':
                contList.insert(i, optDict)
                optDict = {
                    "optionId": i
                }
                i += 1
                optDict[key] = value
            if (key == 'depth'):
                optDict[key] = (int(value).__abs__()).__str__()
            if (key == 'offset'):
                optDict[key] = (int(value).__abs__()).__str__()
            if (key == 'distance'):
                optDict[key] = (int(value).__abs__()).__str__()
            if (key == 'within'):
                optDict[key] = (int(value).__abs__()).__str__()
    contList.insert(i, optDict)
    return contList, msg.replace('"','')


def getPayload(contList):
    regexCond = "/"
    for options in contList:
        dist = options.get('distance')
        within = options.get('within')
        contentStr = ''
        if options.get('offset') is not None and options.get('offset') != '0':
            # The jury is still out on when can 'offset' come into play since it only
            # is relative from the start of the payload.
            regexCond += ".{" + options.get('offset') + "}"
        if dist is not None and dist != '0':
            # We are skipping the 'distance' number of characters
            regexCond += ".{" + dist + "}"
        if within is not None and within != '0':
            # The Suricata documentation mentions that 'distance' is a relative content
            # modifier and it is how much space after the previous content match should this content occur
            # OTOH, 'within' means that the current expression should occur within x bytes of the
            # last match. In other words, 'within' and 'distance' act as upper and lower bound, respectively
            # So in case of 'distance:2 within:2', how is it possible?
            # It is only possible when 'within' is the upper bound starting from 'distance', the lower bound.
            regexCond += "[A-Za-z0-9_]{0,"+within+"}?"
        if (options.get('content') is not None):
            contents = options.get('content').split('|')
            if contents.__len__() > 1:
                for content in contents:
                    # Match to weed out hex content.
                    hegex = re.match("(?:([a-fA-F0-9]{2})\s?)+", content)
                    # Hex content needs to have a specific format in regex
                    if hegex is not None:
                        contentStr += "\\x" + hegex.group().replace(' ', '\\x')
                    # Normal content can go as is
                    else:
                        contentStr += content.replace('{','\{').replace('}','\}')
            else:
                contentStr += contents[0].replace('{','\{').replace('}','\}')
            IsdataatValue = options.get('isdataat')
            if (IsdataatValue is not None) and not IsdataatValue.startswith('!'):
                contentStr += '[^\s]{'+ IsdataatValue.split(',')[0]+'}'
            regexCond += contentStr.replace('/','\/').replace('(', '\(')\
                    .replace('?','\?')\
                    .replace(')', '\)').replace('*','\*')\
                    .replace('+', '\+')
    regexCond += "/"
    return regexCond


def getFlow(contList):
    flowStr = ""
    i = 1
    for options in contList:
        if options.get('flow') is not None:
            flows = options.get('flow').split(',')
            for flow in flows:
                flow = flow.strip()
                if flow == 'established':
                    flowStr += flow
                if flow == 'from_server' or flow == 'to_client':
                    flowStr += "responder"
                if flow == 'to_server' or flow == 'from_client':
                    flowStr += "originator"
                flowStr += ','
    if flowStr == "tcp-state ":
        return ''
    else:
        return re.sub(r'^,|,$', '', flowStr)


def getHttpConditions(contList):
    httpRequest = ""
    uri = 1

    headerStr = ""
    headerCount = 1

    httpReqBody = ""
    reqBody = 1

    httpString = ""

    for options in contList:
        ## HTTP methods like GET and POST will go within payload.
        if options.get('http_uri'):
            if uri != 1:
                httpRequest += "|"
            httpRequest += options.get('content')
            uri += 1
        if options.get('uricontent'):
            if uri != 1:
                httpRequest += "|"
            httpRequest += options.get('uricontent')
            uri += 1
        if options.get('http_header'):
            headerStr += options.get('content')
            headerCount += 1
        if options.get('http_client_body'):
            if reqBody != 1:
                httpReqBody += "|"
            httpReqBody += options.get('content')
            reqBody += 1

    hexesInUri = httpRequest.split('|')
    uriCleaned = ''
    for hex in hexesInUri:
        hegex = re.match("(?:([a-fA-F0-9]{2})\s?)+", hex)
        if hegex is not None:
            uriCleaned += "\\x" + hegex.group().replace(' ', '\\x')
            # Normal content can go as is
        else:
            uriCleaned += hex
    uriCleaned = uriCleaned.replace('(', '\(').replace('{','\{')\
                    .replace('}','\}').replace('?','\?')\
                    .replace(')', '\)').replace('*','\*')\
                    .replace('+', '\+').replace('/', '\/')

    hexesInHeaderStr = headerStr.split('|')
    headerCleaned = ''
    for hex in hexesInHeaderStr:
        hegex = re.match("(?:([a-fA-F0-9]{2})\s?)+", hex)
        if hegex is not None:
            headerCleaned += "\\x" + hegex.group().replace(' ', '\\x')
            # Normal content can go as is
        else:
            headerCleaned += hex
    headerCleaned = headerCleaned.replace('(', '\(').replace('{','\{')\
                    .replace('}','\}').replace('?','\?')\
                    .replace(')', '\)').replace('*','\*')\
                    .replace('+', '\+')

    hexesInReqStr = httpReqBody.split('|')
    requestBodyCleaned = ''
    for hex in hexesInReqStr:
        hegex = re.match("(?:([a-fA-F0-9]{2})\s?)+", hex)
        if hegex is not None:
            requestBodyCleaned += "\\x" + hegex.group().replace(' ', '\\x')
            # Normal content can go as is
        else:
            requestBodyCleaned += hex
    requestBodyCleaned = requestBodyCleaned.replace('(', '\(').replace('{','\{')\
                    .replace('}','\}').replace('?','\?')\
                    .replace(')', '\)').replace('*','\*')\
                    .replace('+', '\+')

    if httpRequest != '':
        httpString += "http-request /" + uriCleaned + "/\n"
    if headerStr != '':
        httpString += "http-request-header /" + headerCleaned.replace('/', '\/') + "/\n"
        httpString += "http-reply-header /" + headerCleaned.replace('/', '\/') + "/\n"
    if httpReqBody != '':
        httpString += "http-request-body /" + requestBodyCleaned.replace('/', '\/') + "/\n"

    return httpString

def processPorts(port):
    portStr = ''
    notPorts = ''
    if port.startswith('!'):
        notPorts += port.replace('!', '').replace(':', ',') + ','
    elif port.startswith('$'):
        pass
    elif port.__contains__(':'):
        # Todo: remove the logic of replacing ! from in front of port ranges. It shouldn't be there
        # in the first place as per suricata rules, but one of the rule is having it, so we'll change
        # it later.
        if port.split(':')[0].replace('!', '') == '':
            lowerLimitPort = 1
        else:
            lowerLimitPort = int(port.split(':')[0].replace('!', ''))

        if port.split(':')[1].replace('!', '') == '':
            upperLimitPort = 65535
        else:
            upperLimitPort = int(port.split(':')[1].replace('!', ''))

        for eachPort in range(lowerLimitPort, upperLimitPort):
            portStr += eachPort.__str__() + ','
    else:
        portStr += port + ','

    return portStr, notPorts

def getPorts(srcPort, dstPort):
    srcPortStr = ''
    notSrcPortStr = ''
    portStatement = ''
    if srcPort != 'any':
        srcPort = re.sub(r'^\[|\]$', '', srcPort)
        ## This evaluation is important to root out a grouped negation
        negateSrcPort = re.findall(r'!\[([^\]]+)\]', srcPort)
        for eachPort in negateSrcPort:
            if ':' in eachPort:
                for singlePort in eachPort.split(','):
                    tmp1, ignorethis = processPorts(singlePort)
                    if tmp1 != '':
                        notSrcPortStr += tmp1
            else:
                notSrcPortStr += eachPort
        srcPort = srcPort.split(',![')[0]
        for eachPort in srcPort.split(','):
            tmp1, tmp2 = processPorts(eachPort)
            if tmp1 != 1:
                srcPortStr += tmp1
            if tmp2 != '':
                if notSrcPortStr != '':
                    notSrcPortStr += ',' + tmp2
                else:
                    notSrcPortStr += tmp2

    dstPortStr = ''
    notDstPortStr = ''
    if dstPort != 'any':
        dstPort = re.sub(r'^\[|\]$', '', dstPort)
        ## This evaluation is important to root out a grouped negation
        negateDstPort = re.findall(r'!\[([^\]]+)\]', dstPort)
        for eachPort in negateDstPort:
            if ':' in eachPort:
                for singlePort in eachPort.split(','):
                    tmp1, ignorethis = processPorts(singlePort)
                    if tmp1 != '':
                        notSrcPortStr += tmp1
            else:
                notDstPortStr += eachPort
        dstPort = dstPort.split('![')[0]
        for eachPort in dstPort.split(','):
            tmp1, tmp2 = processPorts(eachPort)
            if tmp1 != '':
                dstPortStr += tmp1
            if tmp2 != '':
                if notDstPortStr != '':
                    notDstPortStr += ',' + tmp2
                else:
                    notDstPortStr += tmp2

    if srcPortStr.strip() != ',' and srcPortStr.strip() != '':
        portStatement += 'src-port == ' + re.sub(r',+$', '', srcPortStr) + '\n'
    if notSrcPortStr.strip() != ',' and notSrcPortStr.strip() != '':
        portStatement += 'src-port != ' + re.sub(r',+$', '', notSrcPortStr) + '\n'
    if dstPortStr.strip() != ',' and dstPortStr.strip() != '':
        portStatement += 'dst-port == ' + re.sub(r',+$', '', dstPortStr) + '\n'
    if notDstPortStr.strip() != ',' and notDstPortStr.strip() != '':
        portStatement += 'dst-port != ' + re.sub(r',+$', '', notDstPortStr) + '\n'

    return portStatement


def getIP(srcIp, dstIp):
    ipStatement = ""
    srcIp = re.sub(r'\[|\]|,$', '', srcIp)
    dstIp = re.sub(r'\[|\]|,$', '', dstIp)

    if srcIp != 'any':
        for eachSrcIp in srcIp.split(','):
            if eachSrcIp[1:] in MapVars.keys():
                ipStatement += "src-ip == " + MapVars[eachSrcIp[1:]].__str__() + "\n"

    if dstIp != 'any':
        for eachDstIp in dstIp.split(','):
            if eachDstIp[1:] in MapVars.keys():
                ipStatement += "dst-ip == " + MapVars[eachDstIp[1:]].__str__() + "\n"

    return ipStatement.replace('!', '')


def main():
    # Creating the suricata_rules directory
    if not os.path.exists(sig_output):
        os.makedirs(sig_output)

    # Remove the existing __load__.bro if it exists
    if os.path.exists(sig_output+loadBro):
        os.remove(sig_output+loadBro)

    # Download the emerging-exploits.rules 'seanlinmt' git repo
    print("Downloading emerging.exploit.rules.tar.gz from:\n" + url)
    try:
        r = requests.get(url, allow_redirects=True)
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
        print("The connection has not been established and disconnected with an error\n"+err)
        sys.exit()
    except requests.SSLError as err:
        print("The connection has SSL error\n"+err)
        sys.exit()

    open(downloadedRules, 'wb').write(r.content)

    print("Unzipping the tar files..")
    os.system("tar xvf "+downloadedRules)

    ruleFile = "rules/emerging-exploit.rules"

    os.system('rm -rf '+downloadedRules)

    i = 1

    outputFile = 'emerging-exploit.sig'
    outputWriter = open(sig_output+outputFile, 'w+')

    print("Starting to compose rules...")
    with open(ruleFile, "r") as f:
        for line in f:
            if line != '\n' and (line.startswith('#alert') or line.startswith('alert')):

                conds, msg = getConditions(line)
                msg = re.sub(r'\W','',msg)
                    #msg.replace(" ", '').replace("/", '').replace(',', '').replace('.', '').replace('(', '').replace(')', '')

                payload = getPayload(conds)
                if payload == '//':
                    continue
                else:
                    # Creating individual signatures
                    outputWriter.write("signature sig" + i.__str__() + " {\n")

                    attributes = line.split()

                    outputWriter.write(getIP(attributes[2].lower(), attributes[5].lower()))

                    outputWriter.write(getPorts(attributes[3].lower(), attributes[6].lower()))

                    if attributes[1] == 'http' or attributes[1] == 'ftp' \
                            or attributes[1] == 'ssh' or attributes[1] == 'tls':
                        outputWriter.write("ip-proto == " + 'tcp' + '\n')
                    elif attributes[1] == 'tcp' or attributes[1] == 'udp' \
                            or attributes[1] == 'icmp' or attributes[1] == 'icmp6' \
                            or attributes[1] == 'ip' \
                            or attributes[1] == 'ip6':
                        outputWriter.write("ip-proto == " + attributes[1] + '\n')

                    outputWriter.write("payload " + payload + '\n')

                    flowStr = getFlow(conds)
                    if flowStr != "":
                        outputWriter.write("tcp-state " + re.sub(r',+$', '', flowStr) + '\n')

                    outputWriter.write(getHttpConditions(conds))
                    outputWriter.write("event \"" + msg + "\"" + '\n')
                    outputWriter.write("}\n\n")
                i += 1

    print("Generated "+i.__str__() + " signatures...")
    outputWriter.close()

    # Creating and populating the __load__.bro script for the custom signatures
    loadBroFile = open(sig_output + loadBro, 'a+')
    loadBroFile.write("@load-sigs ./" + outputFile[:-4] + '\n')
    loadBroFile.close()

    #Remove the superfluous rules folder
    os.system('rm -rf rules/')

if __name__ == "__main__":
    main()
