import re
import os
import requests

sig_output = "/usr/local/bro/share/bro/site/suricata_rules/"
loadBro = '__load__.bro'

MapVars = {
    "external_net": "local_nets",
    "home_net": "local_nets",
    "http_servers": "http_servers",
    "http_ports": "http_ports",
    "oracle_ports": "oracle_ports",
    "dns_servers": "dns_servers",
    "smtp_servers": "smtp_servers",
    "sql_servers": "sql_servers",
    "telnet_servers": "telnet_servers",
    "aim_servers": "aim_servers",
    "shellcode_ports": "shellcode_ports",
    "ssh_ports": "ssh_ports"
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

            if key == 'pcre':
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
                optDict[key] = value
            if (key == 'offset'):
                optDict[key] = value
            if (key == 'distance'):
                optDict[key] = value
            if (key == 'within'):
                optDict[key] = value
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
            regexCond = ".{" + options.get('offset') + "}"
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
            regexCond += "(?:\w){0,"+within+"}?"
        if (options.get('content') is not None):
            contents = options.get('content').split('|')
            if contents.__len__() > 1:
                regexCond += "("
                for content in contents:
                    # Match to weed out hex content.
                    hegex = re.match("^[0-9a-fA-F ]+", content)
                    # Hex content needs to have a specific format in regex
                    if hegex is not None:

                        contentStr += "\\x{" + hegex.group().replace(' ', '}\\x{') + "}"
                    # Normal content can go as is
                    else:
                        contentStr += content
            else:
                contentStr += contents[0]
            regexCond += contentStr + ")"
    regexCond += "/"
    return regexCond


def getFlow(contList):
    flowStr = ""
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
    if flowStr == "tcp-state ":
        return ''
    else:
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


def getPorts(srcPort, dstPort):
    portStatement = ""
    if srcPort.startswith('$'):
        portStatement += "src-port == "+MapVars[srcPort[1:]].__str__()+"\n"
    else:
        portStatement += "src-port == " + srcPort + "\n"

    if dstPort.startswith('$'):
        portStatement += "dst-port == "+MapVars[dstPort[1:]].__str__()+"\n"
    else:
        portStatement += "dst-port == " + dstPort + "\n"

    return portStatement


def getIP(srcIp, dstIp):
    ipStatement = ""
    if srcIp.startswith('$'):
        ipStatement += "src-ip == "+MapVars[srcIp[1:]].__str__()+"\n"
    else:
        ipStatement += "src-ip == " + srcIp + "\n"

    if dstIp.startswith('$'):
        ipStatement += "dst-ip == "+MapVars[dstIp[1:]].__str__()+"\n"
    else:
        ipStatement += "dst-ip == " + dstIp + "\n"

    return ipStatement


def main():
    if os.path.exists(sig_output+loadBro):
        os.remove(sig_output+loadBro)

    url = 'https://raw.githubusercontent.com/seanlinmt/suricata/master/files/rules/emerging-exploit.rules'
    r = requests.get(url, allow_redirects=True)
    open('emerging-exploit.rules', 'wb').write(r.content)

    i = 1
    with open('emerging-exploit.rules', "r") as f:
        for line in f:
            if line != '\n' and (line.startswith('#alert') or line.startswith('alert')):
                conds, msg = getConditions(line)
                msg = msg.replace(" ", '').replace("/", '').replace(',', '')
                print(msg)

                loadBroFile = open(sig_output+loadBro, 'w+')
                loadBroFile.write("@load-sigs ./"+msg)

                sigFile = msg
                writeFile = open(sig_output+sigFile+'.sig', "w+")
                writeFile.write("signature "+sigFile+" {\n")

                attributes = line.split()

                writeFile.write(getIP(attributes[2].lower(), attributes[5].lower()))

                writeFile.write(getPorts(attributes[3].lower(), attributes[6].lower()))

                if attributes[1] == 'http' or attributes[1] == 'ftp' or attributes[1] == 'ssh' or attributes[1] == 'tls':
                    writeFile.write("ip-proto == " + 'tcp' + '\n')
                else:
                    writeFile.write("ip-proto == " + attributes[1] + '\n')

                payload = getPayload(conds)
                writeFile.write("payload " + payload.replace(' ', '\\x') + '\n')

                flowStr = getFlow(conds)
                if flowStr != "":
                    writeFile.write("tcp-state " + flowStr + '\n')

                writeFile.write(getHttpConditions(conds))
                writeFile.write("event \""+msg+"\"" + '\n')
                writeFile.write("}\n")
                i += 1


if __name__ == "__main__":
    main()
