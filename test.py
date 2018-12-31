import networkx as nx
import pylab as plt
from networkx.drawing.nx_agraph import graphviz_layout

G = nx.MultiDiGraph()
G.add_node("Home")
G.add_node("fa")
G.add_node("af")
G.add_node("das")

# G.add_edge(1,2)
# G.add_edge(1,3)
# G.add_edge(2,4)
nx_node_labels = nx.draw_networkx_labels(G,pos=graphviz_layout(G))
nx.draw(G, pos=graphviz_layout(G),
        prog='neato')
plt.show()