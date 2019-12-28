# Attack Circuits

This repository implements the techniques introduced in [How Secure Is Your IoT Network?](https://ieeexplore.ieee.org/document/8815678)

Be sure to download the CVE json from years 2013-2019 into a folder called cve-data. Name these 2013.json,...,2019.json.

This repository aims to build attack circuits and home IoT network maps, as well as analyze attack paths and evaluate the security state of the devices and network. 

To use, select CVEs from the NVD database correlated with devices in your home network you've chosen. Add these to a new entry in devicemap.json. Use collectCVEs.py to gather all relevant CVEs in one file for ease of access. That file will be known_cves.json. descriptions.py will collect the descriptions of the selected CVEs into one file, descriptions.json, where you can also add input/output elements for each. This is currently being done manually using the descriptions, but we will soon implement NLP for this step. An example is in descriptions_io.json, which the main program uses. Finally, to create the home network, attack circuit, and attack paths, we'll use circuit.py: `$ python circuit.py -d "Router,<device_1>, ... ,<device_n>"`, where the devices are delimited by commas and the router is the first of the entries. The output will be a command line printout of the shortest path from each device to each other device in the attack circuit, a graph of the circuit (circuit.dot), an image of the circuit (circuit.png), a graph of the home network (home_network.dot), and an image of the home network (home_network.png).
