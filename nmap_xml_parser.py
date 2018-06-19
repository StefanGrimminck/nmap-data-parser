""" Unpack and parse XML data"""
import xml.etree.ElementTree as ElemTree
import json
import sys
import argparse


def parse_xml(input_file, output_file):
    """
    :param input_file: File with output data from Nmap in XML format
    :param output_file: File with useful output data from nmap in JSON format
    :return: List with metadata from parser
    """

    # Unpacking of XML file
    tree = ElemTree.parse(input_file)
    root = tree.getroot()

    # List with data that should not be added to final json file
    not_usable_service_info = ["conf", "method", "tunnel", "name"]
    not_usable_port_info = ["id"]

    # Counters for keeping track of parsed data
    total_hosts = 0
    host_with_services = 0
    total_services = 0

    # Loop trough each element called host
    for child in root.findall('host'):
        total_hosts += 1

        # Create a json object for each hosts together with a service and port list.
        host = {}
        service_list = []
        port_list = []
        port_is_open = False
        port_nr = -1
        port = "-1"

        for elem in child.iter():

            # If an element exists called address, then add it as "ip" to the json object.
            if elem.tag == "address":
                host['ip'] = elem.get("addr")

                # If a hostname is coupled to the address,
                # then add it as "hostname" to the json object.
            if elem.tag == "hostname":
                host['hostname'] = elem.get("name")

            # If a service is found, add its value to global variable "port"
            # so it can be used in the fieldnames of its services
            if elem.tag == "port":
                port_nr = elem.get("portid")
                port = 'port' + port_nr

            # Check if the port state is open, else raise a flag.
            # If it is open, add port to list of open ports
            if elem.tag == "state":
                for key in elem.attrib:
                    if key == "state" and elem.attrib.get(key) == "open":
                        port_list.append(int(port_nr))
                        port_is_open = True

            # If a service is detected, add its attributes to the json object.
            if elem.tag == "service" and port_is_open:
                for key in elem.attrib:

                    if key not in not_usable_service_info:
                        host[port + "_service_" + key] = elem.attrib.get(key)

                    if key == "product":
                        service_list.append(elem.attrib.get(key))

            # If a script is used (in our case a banner grabber) add its output to the json object.
            if elem.tag == "script" and port_is_open:
                for key in elem.attrib:
                    if key not in not_usable_port_info:
                        host[port + "_script_" + key] = elem.attrib.get(key)

        # Only add data to the json object
        # if the port where the service runs on is open, else ignore this host
        if port_is_open:

            # Counter of amount of hosts where services were detected
            if service_list:
                host_with_services = host_with_services + 1

                # Counter for total amount of services found
                for _ in service_list:
                    total_services = total_services + 1

                # Create separate lists for service and port data
                host["services"] = service_list
                host["ports"] = port_list

            # Check if usufull data of host exists
            if len(host) is not 0:
                field_count = 0

                # Count amount of fields
                for _ in host:
                    field_count = field_count + 1

                # If only two fields are present,
                # this means the scanner could not find any open ports or services
                # (the two field are ip and hostname). We do not want these hosts in our data.
                if field_count > 2:
                    json_data = json.dumps(host)

                    # Write json object with data to output file
                    with open(output_file, 'a') as outfile:
                        outfile.write(json_data + '\n')
    # Return metadata of parser
    return [total_hosts, host_with_services, total_services]


def main(arguments):

    """
   Nmap XML parser. Will parse IPv4 scans as well as IPv6.
   XML data gets parsed and only useful data will be used to create
   JSON objects.
    """
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('infile', help='Input file', type=argparse.FileType("r"))
    parser.add_argument("outfile", help="Output file", type=argparse.FileType("a"))

# Convert args to usable variables
    args = parser.parse_args(arguments)
    infile = args.infile
    outfile = args.outfile
    hosts = parse_xml(infile.name, outfile.name)

    print("Hosts  processed: \t\t" + str(hosts[0]) + " hosts")
    print("Hosts with services : \t" + str(hosts[1]) + " hosts")
    print("Amount of services : \t" + str(hosts[2]) + " services")
    print("JSON data has been written to: \t" + outfile.name)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
