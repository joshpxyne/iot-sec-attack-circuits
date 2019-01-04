'''
$ python circuit.py -d "Router,<device_1>,<device_2>,...,<device_n>"
'''

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

### Things the attacker might be aiming to obtain. ###

attacker_stash = ["Privacy Breach","this:Root Privileges","this:GPG Key","Credentials","this:Availability","this:Config File","Google Account Access","Physical Location","Privacy Breach"]

def colorVertex(value):
    if value<2:
        return 'greenyellow'
    if value<4:
        return 'yellow3'
    if value<6:
        return 'orange2'
    if value<8:
        return 'red3'
    return 'purple4'

'''
A vector is a list of information about the vulnerabilities of a device, based on its corresponding
CVE score.
'''

def buildVector(device_search,vector):
    if device_search == "Router": return vector
    with open("known_cves.json") as cve_json:
        cve_data = json.load(cve_json)
        for cve in cve_data[device_search]:
            vector[cve["cve"]["CVE_data_meta"]["ID"]] = {}
            try:
                vector[cve["cve"]["CVE_data_meta"]["ID"]]["base"] = cve["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                vector[cve["cve"]["CVE_data_meta"]["ID"]]["impact"] = cve["impact"]["baseMetricV3"]["impactScore"]
                vector[cve["cve"]["CVE_data_meta"]["ID"]]["exploitability"] = cve["impact"]["baseMetricV3"]["exploitabilityScore"]
            except:
                try:
                    vector[cve["cve"]["CVE_data_meta"]["ID"]]["base"] = cve["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                    vector[cve["cve"]["CVE_data_meta"]["ID"]]["impact"] = cve["impact"]["baseMetricV2"]["impactScore"]
                    vector[cve["cve"]["CVE_data_meta"]["ID"]]["exploitability"] = cve["impact"]["baseMetricV2"]["exploitabilityScore"]

                except:
                    continue
    return vector

'''
A circuit is a directed multigraph with subgraphs being circuit elements/IoT devices, vertices being CVEs, and 
an edge (v_1,v_2) exists if there exists a match between the output of one vertex v_1 
(CVE) and the input of another vertex v_2 in the graph. The path consisting
of red edges from one vertex v_m and another vertex v_n is called an attack path.

Vertices are colored based on metrics from the risk score, as are edges that form paths. For path coloring,
we solve an optimization problem to color paths with highest impact, lowest exploitability, etc.

Here, we use a brute force approach to generate all possible paths, but as vulnerability information
and system complexity increases, an AI planning or other intelligent approach may be needed.

For determining optimal paths, we solve a max flow/min cut problem.
''' 

def buildCircuit(devices,vector):

    ### set up circuit ###

    schematic_dotstr = '/*****\nAttack Circuit: Schematic\n*****/\n\ndigraph G {\n  graph [splines=true overlap=false]\n  node  [shape=ellipse, width=0.3, height=0.3]\n' #  size="30,30";\n ratio="fill"
    impact_dotstr = '/*****\nAttack Circuit: Impact\n*****/\n\ndigraph G {\n  graph [splines=true overlap=false]\n  node  [shape=ellipse, width=0.3, height=0.3]\n' #  size="30,30";\n ratio="fill"
    exploitability_dotstr = '/*****\nAttack Circuit: Exploitability\n*****/\n\ndigraph G {\n  graph [splines=true overlap=false]\n  node  [shape=ellipse, width=0.3, height=0.3]\n' #  size="30,30";\n ratio="fill"
    attack_circuit = {}
    ImpactGraph = nx.DiGraph()
    ExploitabilityGraph = nx.DiGraph()
    SchematicGraph = nx.DiGraph()
    
    edge_labels = {}
    dev_ind = cve_ind = 0

    ### add attacker vertex ###
    
    SchematicGraph.add_node("Attacker")
    ImpactGraph.add_node("Attacker")
    ExploitabilityGraph.add_node("Attacker")

    with open("descriptions_io.json") as desc:
        io_desc = json.load(desc)
        schematic_dotstr += '  0 -> 1 [label="Some router/network vulnerability"];\n'
        impact_dotstr += '  0 -> 1 [label="Some router/network vulnerability"];\n'
        exploitability_dotstr += '  0 -> 1 [label="Some router/network vulnerability"];\n'
        dotmap = {}
        targets = []

        ### add all subgraphs, vertices (devices, CVEs) ###

        for device in devices:
            dev_ind+=1
            schematic_dotstr += "  subgraph cluster_" + str(dev_ind) + ' {\n  label="'+device+'";'
            impact_dotstr += "  subgraph cluster_" + str(dev_ind) + ' {\n  label="'+device+'";'
            exploitability_dotstr += "  subgraph cluster_" + str(dev_ind) + ' {\n  label="'+device+'";'
            if dev_ind==1:
                schematic_dotstr += '  0 [label="Attacker '+ str(dev_ind) +'", shape=Mdiamond];\n' ## TODO: add support for multiple attackers other than at the network/router level
                impact_dotstr += '  0 [label="Attacker '+ str(dev_ind) +'", shape=Mdiamond];\n'
                exploitability_dotstr += '  0 [label="Attacker '+ str(dev_ind) +'", shape=Mdiamond];\n'
            for cve in io_desc[device]:
                SchematicGraph.add_node(cve["id"])
                ImpactGraph.add_node(cve["id"])
                ExploitabilityGraph.add_node(cve["id"])
                cve_ind+=1
                dotmap[cve["id"]] = cve_ind
                attack_circuit[cve["id"]] = {}
                attack_circuit[cve["id"]]["inputs"] = []
                attack_circuit[cve["id"]]["outputs"] = []
                for io in cve["i/o"]:
                    attack_circuit[cve["id"]]["inputs"].append(io.split('->')[0])
                    if cve["description"]!="Non-CVE I/O":
                        attack_circuit[cve["id"]]["outputs"].append(io.split('->')[1])
                        if dev_ind!=1 and io.split('->')[1] not in targets:
                            targets.append(io.split('->')[1])
                    else:
                        attack_circuit[cve["id"]]["outputs"].append(io.split('->')[1])
                        if dev_ind!=1 and io.split('->')[1] not in targets:
                            targets.append(io.split('->')[1])
                schematic_dotstr += "    " + str(cve_ind) + ' [label="' + cve["id"] + '"];\n'
                impact_dotstr += "    " + str(cve_ind) + ' [label="' + cve["id"] + '"];\n'
                exploitability_dotstr += "    " + str(cve_ind) + ' [label="' + cve["id"] + '"];\n'
            schematic_dotstr += "  }\n"
            impact_dotstr += "  }\n"
            exploitability_dotstr += "  }\n"
        schematic_dotstr += "  subgraph cluster_" + str(dev_ind+1) + ' {\n  label="Attacker Targets";'
        impact_dotstr += "  subgraph cluster_" + str(dev_ind+1) + ' {\n  label="Attacker Targets";'
        exploitability_dotstr += "  subgraph cluster_" + str(dev_ind+1) + ' {\n  label="Attacker Targets";'
        for target in targets:
            SchematicGraph.add_node(target)
            ImpactGraph.add_node(target)
            ExploitabilityGraph.add_node(target)
            cve_ind+=1
            print(target)
            dotmap[target] = cve_ind
            schematic_dotstr += "    " + str(cve_ind) + ' [label="' + target + '"];\n'
            impact_dotstr += "    " + str(cve_ind) + ' [label="' + target + '"];\n'
            exploitability_dotstr += "    " + str(cve_ind) + ' [label="' + target + '"];\n'
        schematic_dotstr += "  }\n"
        impact_dotstr += "  }\n"
        exploitability_dotstr += "  }\n"

        ### add all device edges ###       
        
        for dev_x in devices:
            for dev_y in devices: # loop thru inputs, outputs of the two CVEs. Currently, add edge if i/o matches.
                for cve_dev_x in io_desc[dev_x]:
                    for cve_dev_y in io_desc[dev_y]: 
                        for cve_x_output in attack_circuit[cve_dev_x["id"]]["outputs"]:
                            for cve_y_input in attack_circuit[cve_dev_y["id"]]["inputs"]:
                                if cve_x_output==cve_y_input:
                                    SchematicGraph.add_edge(cve_dev_x["id"],cve_dev_y["id"])
                                    try:
                                        ImpactGraph.add_edge(cve_dev_x["id"],cve_dev_y["id"],capacity=vector[cve_dev_y["id"]]["impact"])
                                        if str(cve_dev_x["id"])=="Non-CVE info: Router":
                                            ExploitabilityGraph.add_edge(cve_dev_x["id"],cve_dev_y["id"],demand=-1.0)
                                        else:
                                            ExploitabilityGraph.add_edge(cve_dev_x["id"],cve_dev_y["id"],weight=10 - vector[cve_dev_y["id"]]["exploitability"])
                                    except: # sometimes CVE doesn't have a CVSS score
                                        ImpactGraph.add_edge(cve_dev_x["id"],cve_dev_y["id"],capacity=3.0)
                                        if str(cve_dev_x["id"])=="Non-CVE info: Router":
                                            ExploitabilityGraph.add_edge(cve_dev_x["id"],cve_dev_y["id"],demand=-1.0)
                                        else:
                                            ExploitabilityGraph.add_edge(cve_dev_x["id"],cve_dev_y["id"],weight=7.0)
                                            
                                    edge_labels[(cve_dev_x["id"],cve_dev_y["id"])] = cve_x_output
                                    try:
                                        schematic_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> " + str(dotmap[cve_dev_y["id"]]) + ' [label="' + cve_x_output + '" color="black"];\n'
                                        impact_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> " + str(dotmap[cve_dev_y["id"]]) + ' [label="' + cve_x_output + '" color="' + colorVertex(vector[cve_dev_x["id"]]["impact"]) + '"];\n'
                                        exploitability_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> " + str(dotmap[cve_dev_y["id"]]) + ' [label="' + cve_x_output + '" color="' + colorVertex(vector[cve_dev_x["id"]]["exploitability"]) + '"];\n'
                                    except:
                                        schematic_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> " + str(dotmap[cve_dev_y["id"]]) + ' [label="' + cve_x_output + '" color="black"];\n'
                                        impact_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> " + str(dotmap[cve_dev_y["id"]]) + ' [label="' + cve_x_output + '" color="' + colorVertex(3.0) + '"];\n'
                                        exploitability_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> " + str(dotmap[cve_dev_y["id"]]) + ' [label="' + cve_x_output + '" color="' + colorVertex(3.0) + '"];\n'

        ### add all attacker edges ###

        for dev_x in devices:
            for cve_dev_x in io_desc[dev_x]:
                for io in cve_dev_x["i/o"]:
                    if cve_dev_x["id"]!="Non-CVE info: Router":
                        ImpactGraph.add_edge(cve_dev_x["id"],io.split('->')[1],capacity=100000.0)
                        ExploitabilityGraph.add_edge(cve_dev_x["id"],io.split('->')[1],demand=1.0)
                        try:
                            schematic_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> " + str(dotmap[io.split('->')[1]]) + ' [label="' + cve_x_output + '" color="black"];\n'
                            impact_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> " + str(dotmap[io.split('->')[1]]) + ' [label="' + cve_x_output + '" color="' + colorVertex(vector[cve_dev_x["id"]]["impact"]) + '"];\n'
                            exploitability_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> " + str(dotmap[io.split('->')[1]]) + ' [label="' + cve_x_output + '" color="' + colorVertex(vector[cve_dev_x["id"]]["exploitability"]) + '"];\n'
                        except: # sometimes CVE doesn't have a CVSS score
                            schematic_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " ->  " + str(dotmap[io.split('->')[1]]) + ' [label="' + cve_x_output + '" color="black"];\n'
                            impact_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " ->  " + str(dotmap[io.split('->')[1]]) + ' [label="' + cve_x_output + '" color="' + colorVertex(3.0) + '"];\n'
                            exploitability_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " ->  " + str(dotmap[io.split('->')[1]]) + ' [label="' + cve_x_output + '" color="' + colorVertex(3.0) + '"];\n'
        # for dev_x in devices:
        #     for cve_dev_x in io_desc[dev_x]:
        #         if cve_dev_x["id"]!="Non-CVE info: Router":
        #             ImpactGraph.add_edge(cve_dev_x["id"],"Attacker",capacity=100000.0)
        #             ExploitabilityGraph.add_edge(cve_dev_x["id"],"Attacker",capacity=100000.0)
        #         try:
        #             schematic_dotstr += "    " + str(dotmap[cve_dev_x["id"]]) + ' [color="black"];\n'
        #             impact_dotstr += "    " + str(dotmap[cve_dev_x["id"]]) + ' [color="' + colorVertex(vector[cve_dev_x["id"]]["impact"]) + '"];\n'
        #             exploitability_dotstr += "    " + str(dotmap[cve_dev_x["id"]]) + ' [color="' + colorVertex(vector[cve_dev_x["id"]]["exploitability"]) + '"];\n'
        #         except: # sometimes CVE doesn't have a CVSS score
        #             schematic_dotstr += "    " + str(dotmap[cve_dev_x["id"]]) + ' [color="black"];\n'
        #             impact_dotstr += "    " + str(dotmap[cve_dev_x["id"]]) + ' [color="' + colorVertex(3.0) + '"];\n'
        #             exploitability_dotstr += "    " + str(dotmap[cve_dev_x["id"]]) + ' [color="' + colorVertex(3.0) + '"];\n'
        #         for cve_x_output in attack_circuit[cve_dev_x["id"]]["outputs"]:
        #             if cve_x_output.split(r"\n")[0] in attacker_stash:
        #                 try:
        #                     schematic_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> 0" + ' [label="' + cve_x_output + '" color="black"];\n'
        #                     impact_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> 0" + ' [label="' + cve_x_output + '" color="' + colorVertex(vector[cve_dev_x["id"]]["impact"]) + '"];\n'
        #                     exploitability_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> 0" + ' [label="' + cve_x_output + '" color="' + colorVertex(vector[cve_dev_x["id"]]["exploitability"]) + '"];\n'
        #                 except: # sometimes CVE doesn't have a CVSS score
        #                     schematic_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> 0" + ' [label="' + cve_x_output + '" color="black"];\n'
        #                     impact_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> 0" + ' [label="' + cve_x_output + '" color="' + colorVertex(3.0) + '"];\n'
        #                     exploitability_dotstr += "  " + str(dotmap[cve_dev_x["id"]]) + " -> 0" + ' [label="' + cve_x_output + '" color="' + colorVertex(3.0) + '"];\n'

        ### build attack paths ###

        schematic_dotstr += r'  label = "\nAttack Circuit: Schematic\n";  fontsize=24;' + '\n}'
        impact_dotstr += r'  label = "\nAttack Circuit: Impact\n";  fontsize=24;' + '\n}'
        exploitability_dotstr += r'  label = "\nAttack Circuit: Exploitability\n";  fontsize=24;' + '\n}'

        paths = {}
        for dev_x in devices:
            for dev_y in devices:
                for cve_dev_x in io_desc[dev_x]:
                    for cve_dev_y in io_desc[dev_y]: 
                        try:
                            paths[str(cve_dev_x["id"])+","+str(cve_dev_y["id"])] = nx.shortest_path(SchematicGraph, source=cve_dev_x["id"], target=cve_dev_y["id"])
                        except:
                            paths[str(cve_dev_x["id"])+","+str(cve_dev_y["id"])] = "None"

        # print ("All paths: ",paths)
    return paths, SchematicGraph, ImpactGraph, ExploitabilityGraph, edge_labels, schematic_dotstr, impact_dotstr, exploitability_dotstr, targets

'''
A network is an undirected graph with diameter d <= 2 where vertices are IoT devices in a 
home and edges represent communication. There is a central vertex in each graph that is adjacent 
to each other edge that represents the router.
''' 

def buildNetwork(devices):
    vector = {}
    home_network = snap.TUNGraph.New()
    labels = snap.TIntStrH()
    dev_ind = 0
    for device in devices:
        dev_ind+=1
        home_network.AddNode(dev_ind)
        if dev_ind!=1:
            home_network.AddEdge(dev_ind, 1)
        labels.AddDat(dev_ind, str(device))
        vector = buildVector(device,vector)
    return home_network, labels, vector

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-d", "--devices", dest="devices",help="input device")
    (options, args) = parser.parse_args()
    devices = options.devices.split(',')

     ### build ###

    home_network, network_labels, vector = buildNetwork(devices)
    # print(vector)
    paths, SchematicGraph, ImpactGraph, ExploitabilityGraph, edge_labels, schematic_dotstr, impact_dotstr, exploitability_dotstr, targets = buildCircuit(devices,vector)

    ### find max flow values ###
    max_impact = max_exploitability = 0
    for target in targets:
        max_impact += nx.maximum_flow_value(ImpactGraph, "Non-CVE info: Router", target)
        min_cost = nx.min_cost_flow(ExploitabilityGraph)
        print("Min cost flow, "+target+": ",min_cost)
    print("Max Impact: ",max_impact)

    ### save ###

    snap.DrawGViz(home_network, snap.gvlDot, "deliverables/home_network.png", "Home Network", network_labels)
    schematic_dotfile = open("deliverables/schematic_circuit.dot", "w")
    schematic_dotfile.write(schematic_dotstr)
    schematic_dotfile.close()
    impact_dotfile = open("deliverables/impact_circuit.dot", "w")
    impact_dotfile.write(impact_dotstr)
    impact_dotfile.close()
    exploitability_dotfile = open("deliverables/exploitability_circuit.dot", "w")
    exploitability_dotfile.write(exploitability_dotstr)
    exploitability_dotfile.close()

    ### draw ###

    (schematic_graph,) = pydot.graph_from_dot_file('deliverables/schematic_circuit.dot')
    schematic_graph.write_png('deliverables/schematic_circuit.png')
    (impact_graph,) = pydot.graph_from_dot_file('deliverables/impact_circuit.dot')
    impact_graph.write_png('deliverables/impact_circuit.png')
    (exploitability_graph,) = pydot.graph_from_dot_file('deliverables/exploitability_circuit.dot')
    exploitability_graph.write_png('deliverables/exploitability_circuit.png')

    # nx_node_labels = nx.draw_networkx_labels(G,pos=graphviz_layout(G, prog='dot'))
    # nx_edge_labels = nx.draw_networkx_edge_labels(G,pos=graphviz_layout(G, prog='dot'),edge_labels=edge_labels,font_color='red') 
    # nx.draw(G, pos=graphviz_layout(G, prog='dot'),node_size=1600,node_color=range(len(G)))
    # plt.axis('off')
    # plt.show()
