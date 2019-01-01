import request
import json
import random
import networkx as nx
from networkx.drawing.nx_agraph import graphviz_layout
import snap
import pydot
import collections
import itertools
import matplotlib.pyplot as plt
from optparse import OptionParser

### Things the attacker might be aiming to get. ###
attacker_stash = ["Privacy Breach","this:Root Privileges","this:GPG Key","Credentials","this:Availability","this:Config File","Google Account Access","Physical Location","Privacy Breach"]

'''
A vector is a list of information about the vulnerabilities of a device, based on its corresponding
CVE score.
'''

def buildVector(device_search):
    if device_search == "Router": return ""
    vector = {
        "base": [],
        "attack_vectors": []
    }
    with open("known_cves.json") as cve_json:
        cve_data = json.load(cve_json)
        for cve in cve_data[device_search]:
            # print(cve["cve"])

            try:
                vector["base"].append(cve["impact"]["baseMetricV3"]["cvssV3"]["baseScore"])
                vector["attack_vectors"].append(cve["impact"]["baseMetricV3"]["cvssV3"]["vectorString"])
            except:
                try:
                    vector["base"].append(cve["impact"]["baseMetricV2"]["cvssV2"]["baseScore"])
                    vector["attack_vectors"].append(cve["impact"]["baseMetricV2"]["cvssV2"]["vectorString"])
                except:
                    continue

    return vector

'''
A circuit is a fully connected, directed graph with subgraphs being circuit elements/IoT devices, vertices being CVEs, and 
an edge (v_1,v_2) is 'red' if there exists a match between the output of one vertex v_1 
(CVE) and the input of another vertex v_2 in the graph. The path consisting
of red edges from one vertex v_m and another vertex v_n is called an attack path.

Here, we use a brute force approach to generate all possible paths, but as vulnerability information
and system complexity increases, an AI planning or other intelligent approach may be needed.
''' 

def buildCircuit(devices):

    ### set up circuit ###

    dotstr = '/*****\nAttack Circuit\n*****/\n\ndigraph G {\n  graph [splines=true overlap=false]\n  node  [shape=ellipse, width=0.3, height=0.3]\n' #  size="30,30";\n ratio="fill"
    attack_circuit = {}
    G = nx.MultiDiGraph()
    edge_labels = {}
    dev_ind = cve_ind = 0

    ### add attacker vertex ###
    
    G.add_node("Attacker")
    dotstr += "  " + str(dev_ind) + ' [label="Attacker", shape=Mdiamond];\n'
    
    with open("descriptions_io.json") as desc:
        io_desc = json.load(desc)
        dotstr += '  0 -> 1 [label="Some router/network vulnerability"];\n'
        dotmap = {}

         ### add all vertices (devices) ###

        for device in devices:
            dev_ind+=1
            dotstr += "  subgraph cluster_" + str(dev_ind) + ' {\n  label="'+device+'";'
            for cve in io_desc[device]:
                cve_ind+=1
                dotmap[cve["id"]] = cve_ind
                G.add_node(cve["id"])
                attack_circuit[cve["id"]] = {}
                attack_circuit[cve["id"]]["inputs"] = []
                attack_circuit[cve["id"]]["outputs"] = []
                for io in cve["i/o"]:
                    attack_circuit[cve["id"]]["inputs"].append(io.split('->')[0])
                    if cve["description"]!="Non-CVE I/O":
                        attack_circuit[cve["id"]]["outputs"].append(io.split('->')[1])
                    else:
                        attack_circuit[cve["id"]]["outputs"].append(io.split('->')[1])
                dotstr += "    " + str(cve_ind) + ' [label="' + cve["id"] + '"];\n'
            dotstr += "  }\n"

        ### add all device edges ###       
        
        for dev_x in devices:
            for dev_y in devices: # loop thru inputs, outputs of the two CVEs. Currently, add edge if i/o matches.
                for cve_dev_x in io_desc[dev_x]:
                    for cve_dev_y in io_desc[dev_y]: 
                        for cve_x_output in attack_circuit[cve_dev_x["id"]]["outputs"]:
                            for cve_y_input in attack_circuit[cve_dev_y["id"]]["inputs"]:
                                if cve_x_output==cve_y_input:
                                    G.add_edge(cve_dev_x["id"],cve_dev_y["id"])
                                    edge_labels[(cve_dev_x["id"],cve_dev_y["id"])] = cve_x_output
                                    dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> " + str(dotmap[cve_dev_y["id"]]) + ' [label="' + cve_x_output + '"];\n'
        
        ### add all attacker edges ###

        for dev_x in devices:
            for cve_dev_x in io_desc[dev_x]:
                for cve_x_output in attack_circuit[cve_dev_x["id"]]["outputs"]:
                    if cve_x_output.split(r"\n")[0] in attacker_stash:
                        dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> 0" + ' [label="' + cve_x_output + '"];\n'

        ### build attack paths ###

        dotstr += r'  label = "\nAttack Circuit\n";  fontsize=24;' + '\n}'
        paths = {}
        for dev_x in devices:
            for dev_y in devices:
                for cve_dev_x in io_desc[dev_x]:
                    for cve_dev_y in io_desc[dev_y]: 
                        try:
                            paths[str(cve_dev_x["id"])+","+str(cve_dev_y["id"])] = nx.shortest_path(G, source=cve_dev_x["id"], target=cve_dev_y["id"])
                        except:
                            paths[str(cve_dev_x["id"])+","+str(cve_dev_y["id"])] = "None"
        print ("All paths: ",paths)
    return paths, G, edge_labels, dotstr

'''
A network is an undirected graph with maximum diameter = 2 where vertices are IoT devices in a 
home and edges represent communication. There is a central vertex in each graph that is adjacent 
to each other edge that represents the router.
''' 

def buildNetwork(devices):
    vectors = {}
    home_network = snap.TUNGraph.New()
    labels = snap.TIntStrH()
    dev_ind = 0
    for device in devices:
        dev_ind+=1
        vector = buildVector(device)
        vectors[device] = vector
        home_network.AddNode(dev_ind)
        if dev_ind!=1:
            home_network.AddEdge(dev_ind, 1) # assuming Router is the first device in the argument
        labels.AddDat(dev_ind, str(device))
    return home_network, labels, vectors

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-d", "--devices", dest="devices",help="input device")
    (options, args) = parser.parse_args()
    devices = options.devices.split(',')

     ### build ###

    home_network, network_labels, vectors = buildNetwork(devices)
    paths, G, edge_labels, dotstr = buildCircuit(devices)

    ### draw/save ###
    snap.DrawGViz(home_network, snap.gvlDot, "home_network.png", "Home Network", network_labels)
    dotfile = open("circuit.dot", "w")
    dotfile.write(dotstr)
    dotfile.close()
    (graph,) = pydot.graph_from_dot_file('circuit.dot')
    graph.write_png('circuit.png')

    # nx_node_labels = nx.draw_networkx_labels(G,pos=graphviz_layout(G, prog='dot'))
    # nx_edge_labels = nx.draw_networkx_edge_labels(G,pos=graphviz_layout(G, prog='dot'),edge_labels=edge_labels,font_color='red') 
    # nx.draw(G, pos=graphviz_layout(G, prog='dot'),node_size=1600,node_color=range(len(G)))
    # plt.axis('off')
    # plt.show()
