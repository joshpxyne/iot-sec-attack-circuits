import request
import json
import random
import networkx as nx
from networkx.drawing.nx_agraph import graphviz_layout
import pydot
import snap
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
A circuit is a fully connected, directed graph with vertices being circuit elements/IoT devices, and 
an edge (v_1,v_2) is 'red' if there exists a match between the output of one vertex v_1 
(circuit element/IoT device) and the input of another vertex v_2 in the graph. The path consisting
of red edges from one vertex v_m and another vertex v_n is called an attack path.

Here, we use a brute force approach to generate all possible paths, but as vulnerability information
and system complexity increases, an AI planning or other intelligent approach may be needed.
''' 

def find_shortest_path(graph, start, end, path=[]):
    path = path + [start]
    if start == end:
        return path
    if start not in graph:
        return None
    shortest = None
    for node in graph[start]:
        if node not in path:
            newpath = find_shortest_path(graph, node, end, path)
            if newpath:
                if not shortest or len(newpath) < len(shortest):
                    shortest = newpath
    return shortest

def buildCircuit(devices,vectors):
    ### add circuit elements ###
    attack_circuit = {}
    circuit = snap.TNEANet.New()
    labels = snap.TIntStrH()
    dev_ind = 0
    ### add all nodes (devices) ###
    G = nx.MultiDiGraph()
    edge_labels = {}
    dotstr = "/*****\nAttack Circuit\n*****/\n\ndigraph G {\n  graph [splines=true overlap=false]\n  node  [shape=ellipse, width=0.3, height=0.3]\n"
    G.add_node("Attacker")
    dotstr += "  " + str(dev_ind) + ' [label="Attacker"];\n'
    router_ind = 0
    with open("descriptions_io.json") as desc:
        io_desc = json.load(desc)
        for device in devices:
            dev_ind+=1
            if device=="Router":
                router_ind = dev_ind
            G.add_node(device)
            attack_circuit[device] = {}
            attack_circuit[device]["inputs"] = []
            attack_circuit[device]["outputs"] = []
            for cve in io_desc[device]:
                for io in cve["i/o"]:
                    if cve["description"]!="Non-CVE I/O":
                        attack_circuit[device]["outputs"].append(io.split('->')[1]+r"\n"+cve["id"])
                    else:
                        attack_circuit[device]["outputs"].append(io.split('->')[1])
                    attack_circuit[device]["inputs"].append(io.split('->')[0])
                    # print(device,"input",io.split('->')[0],"output",io.split('->')[1])
            circuit.AddNode(dev_ind)
            dotstr += "  " + str(dev_ind) + ' [label="' + device + '"];\n'
            labels.AddDat(dev_ind, str(device))
        dotstr += "  0 -> "+ str(router_ind) + ' [label="Some router/network vulnerability"];\n'
        ### add all edges ###        
        dev_x_ind = 1
        for dev_x in devices:
            dev_y_ind = 1
            for dev_y in devices:
                ### loop thru inputs, outputs of the two devices. Currently, if they match.
                for dev_x_output in attack_circuit[dev_x]["outputs"]:
                    for dev_y_input in attack_circuit[dev_y]["inputs"]:
                        if dev_x_output.split(r"\n")[0]==dev_y_input:
                            circuit.AddEdge(dev_x_ind,dev_y_ind) # output to input
                            G.add_edge(dev_x,dev_y)
                            edge_labels[(dev_x,dev_y)] = dev_x_output
                            dotstr += "  " + str(dev_x_ind) + " -> " + str(dev_y_ind) + ' [label="' + dev_x_output + '"];\n'
                dev_y_ind+=1
            dev_x_ind+=1
        dev_x_ind = 1
        for dev_x in devices:
            for dev_x_output in attack_circuit[dev_x]["outputs"]:
                if dev_x_output.split(r"\n")[0] in attacker_stash:
                    dotstr += "  " + str(dev_x_ind) + " -> 0" + ' [label="' + dev_x_output + '"];\n'
            dev_x_ind += 1
        ### build attack paths ###
        dotstr += r'  label = "\nAttack Circuit\n";  fontsize=24;'
        dotstr += '\n}'
        paths = {}
        for dev_x in devices:
            for dev_y in devices:
                if dev_x!="Attacker" and dev_y!="Attacker":
                    try:
                        paths[str(dev_x)+","+str(dev_y)] = nx.shortest_path(G, source=dev_x, target=dev_y)
                    except:
                        paths[str(dev_x)+","+str(dev_y)] = "None"
        print ("All paths: ",paths)
    return circuit, labels, paths, G, edge_labels, dotstr

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
            home_network.AddEdge(dev_ind, 1) ### assuming Router is the first device in the argument
        labels.AddDat(dev_ind, str(device))
    return home_network, labels, vectors

if __name__ == "__main__":
    attack_circuit = []
    parser = OptionParser()
    parser.add_option("-d", "--devices", dest="devices",
                    help="input device")
    (options, args) = parser.parse_args()
    devices = options.devices.split(',')
    home_network, network_labels, vectors = buildNetwork(devices)
    circuit, circuit_labels, paths, G, edge_labels, dotstr = buildCircuit(devices,vectors)
    snap.DrawGViz(home_network, snap.gvlDot, "home_network.png", "Home Network", network_labels)
    # snap.DrawGViz(circuit, snap.gvlDot, "circuit.png", "Attack Circuit", circuit_labels)
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
