import xml.etree.ElementTree as ET
import json
import sys
import argparse


def parse_xml(input_file, output_file):

    tree = ET.parse(input_file)
    root = tree.getroot()
    host_with_port = 0
    for child in root.findall('host'):

        host = {}

        for elem in child.iter():
            if elem.tag == "address":
                host['ip'] = elem.get("addr")

            if elem.tag == "hostname":
                host['hostname'] = elem.get("name")

            if elem.tag == "port":
                port = elem.get("portid")
                port = 'port' + port
                host_with_port = host_with_port + 1

            if elem.tag == "state":
                for key in elem.attrib:
                    host[port + "_state_" + key] = elem.attrib.get(key)

            if elem.tag == "service":
                for key in elem.attrib:
                    host[port + "_service_" + key] = elem.attrib.get(key)

            if elem.tag == "script":
                for key in elem.attrib:
                    host[port + "_script_" + key] = elem.attrib.get(key)

            if elem.tag == "elem":
                for key in elem.attrib:
                    host[port + "_elem_" + key] = elem.attrib.get(key)

        if len(host) is not 0:
            field_count = 0
            for item in host:
                field_count = field_count +1

                """
                If only two fields are present, this means the scanner could not found any open ports or services (the 
                two field are ip and hostname)
                """
            if field_count > 2:
                json_data = json.dumps(host)

                with open(output_file, 'a') as outfile:
                    outfile.write(json_data + '\n')

    return host_with_port


def main(arguments):

    """
   Nmap XML parser. Will parse IPv4 scans as well as IPv6
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('infile', help='Input file', type=argparse.FileType("r"))
    parser.add_argument("outfile", help="Output file", type=argparse.FileType("a"))

# Convert args to usable variables
    args = parser.parse_args(arguments)
    infile = args.infile
    outfile = args.outfile

    hosts = parse_xml(infile.name, outfile.name)

    print("Hosts with ports processed: \t" + str(hosts) +  " hosts")
    print("JSON data has been written to: \t" + outfile.name)



if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
