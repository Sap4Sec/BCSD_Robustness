import numpy as np
import networkx as nx

from models.GEMINI.asm_embedding.BlockFeaturesExtractor import BlockFeaturesExtractor


def extract_features(cfg, string_addresses, arch="x86"):
    acfg = nx.DiGraph()

    for n in cfg.nodes(data=True):
        n_inst = n[1]['disasm']

        bfe = BlockFeaturesExtractor(arch, n_inst, string_addresses)
        annotations = bfe.getFeatures()

        acfg.add_node(n[0], features=annotations)

    for n in cfg.nodes:
        for out_edge in cfg.successors(n):
            acfg.add_edge(n, out_edge)

    between = nx.betweenness_centrality(acfg)
    for n in acfg.nodes(data=True):
        d = n[1]['features']
        d['offspring'] = len(nx.descendants(acfg, n[0]))
        d['betweenness'] = between[n[0]]
        n[1]['features'] = d

    return acfg


def padAndFilter(input_pairs, input_labels, max_num_vertices):
    output_pairs = []
    output_labels = []
    for pair, label in zip(input_pairs, input_labels):
        g1 = pair[0]
        g2 = pair[1]

        # graph 1
        adj1 = g1[0]
        nodes1 = g1[1]

        # graph 2
        adj2 = g2[0]
        nodes2 = g2[1]

        if (len(nodes1) <= max_num_vertices) and (len(nodes2) <= max_num_vertices):
            # graph 1
            pad_lenght1 = max_num_vertices - len(nodes1)
            new_node1 = np.pad(nodes1, [(0, pad_lenght1), (0, 0)], mode='constant')
            pad_lenght1 = max_num_vertices - adj1.shape[0]
            adj1_dense = np.pad(adj1.todense(), [(0, pad_lenght1), (0, pad_lenght1)], mode='constant')
            g1 = (adj1_dense, new_node1)
            adj2 = g2[0]
            nodes2 = g2[1]
            pad_lenght2 = max_num_vertices - len(nodes2)
            new_node2 = np.pad(nodes2, [(0, pad_lenght2), (0, 0)], mode='constant')
            pad_lenght2 = max_num_vertices - adj2.shape[0]
            adj2_dense = np.pad(adj2.todense(), [(0, pad_lenght2), (0, pad_lenght2)], mode='constant')
            g2 = (adj2_dense, new_node2)
            output_pairs.append([g1, g2])
            output_labels.append(label)
        else:
            # graph 1
            new_node1 = nodes1[0:max_num_vertices]
            adj1_dense = adj1.todense()[0:max_num_vertices, 0:max_num_vertices]
            g1 = (adj1_dense, new_node1)
            g2 = (adj1_dense, new_node1)
            output_pairs.append([g1, g2])
            output_labels.append(label)
    return output_pairs, output_labels


def extract_features(cfg, string_addresses, arch="x86"):
    acfg = nx.DiGraph()

    for n in cfg.nodes(data=True):
        n_inst = n[1]['disasm']

        bfe = BlockFeaturesExtractor(arch, n_inst, string_addresses)
        annotations = bfe.getFeatures()

        acfg.add_node(n[0], features=annotations)

    for n in cfg.nodes:
        for out_edge in cfg.successors(n):
            acfg.add_edge(n, out_edge)

    between = nx.betweenness_centrality(acfg)
    for n in acfg.nodes(data=True):
        d = n[1]['features']
        d['offspring'] = len(nx.descendants(acfg, n[0]))
        d['betweenness'] = between[n[0]]
        n[1]['features'] = d

    return acfg


def parallel_extract_features(parameters):
    cfg = parameters[0]
    string_addresses = parameters[1]

    acfg = extract_features(cfg, string_addresses)

    pairs = []
    label = []
    cfg_nodes = []
    adj = nx.adjacency_matrix(acfg)

    for n in acfg.nodes(data=True):
        f = n[1]['features']
        features = np.zeros(8)
        if len(f.keys()) > 0:
            if isinstance(f['constant'], list):
                features[0] = len(f['constant'])
            else:
                features[0] = f['constant']
            if isinstance(f['string'], list):
                features[1] = len(f['string'])
            else:
                features[1] = f['string']

            features[2] = f['transfer']  # mov
            features[3] = f['call']  # call
            features[4] = f['instruction']
            features[5] = f['arith']  # add
            features[6] = f['offspring']  # jmp
            features[7] = f['betweenness']
        cfg_nodes.append(features)
    pairs.append(((adj, cfg_nodes), (adj, cfg_nodes)))
    label.append(0)
    pairs, _ = padAndFilter(pairs, label, 150)
    graph1, graph2 = zip(*pairs)
    adj, nodes = zip(*graph1)

    return adj[0], nodes[0]