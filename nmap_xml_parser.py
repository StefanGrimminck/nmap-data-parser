import xml.etree.ElementTree as ET
import json
tree = ET.parse('inputfile')
root = tree.getroot()

for child in root.findall('host'):


    host = {}

    for elem in child.iter():

        if elem.tag == "address":
            host['ip'] = elem.get("addr")

        if elem.tag == "hostname":
            host['hostname'] = elem.get("name")

        if elem.tag =="port":
            port = elem.get("portid")
            port = 'port' + port


        if elem.tag == "state":


            for key in elem.attrib:
                host[port + "_" + key] = elem.attrib.get(key)

        if elem.tag == "service":
            for key in elem.attrib:
                host[port + "_" + key] = elem.attrib.get(key)

        if elem.tag == "script":
            for key in elem.attrib:
                host[port + "_" + key] = elem.attrib.get(key)



    if len(host) is not 0:

        counter = 0
        for item in host:
            counter = counter +1

        if counter > 1:

            json_data = json.dumps(host)
            print(json_data)


