'''
Description: 
version: 
Author: zlx
Date: 2023-12-12 21:13:09
LastEditors: zlx
LastEditTime: 2023-12-13 11:08:39
'''
import numpy as np
import torch
import torch.nn as nn
import pickle
from collections import defaultdict
from alg.graphsage.model import (MeanAggregator, Encoder)


def load_sage(path, binary):
    # nodes
    nodes = np.load(path+"/nodes.npy", allow_pickle=True)
    num_nodes = len(nodes)

    # features node_feat: all one; edge_feat: scaled
    node_feat = np.ones((num_nodes, 64))
    node_features = nn.Embedding(node_feat.shape[0], node_feat.shape[1])
    node_features.weight = nn.Parameter(torch.FloatTensor(node_feat), requires_grad=False)
    edge_feat = np.load(path+"/edge_feat_scaled.npy")  # (n,f)
    edge_features = nn.Embedding(edge_feat.shape[0], edge_feat.shape[1])
    edge_features.weight = nn.Parameter(torch.FloatTensor(edge_feat), requires_grad=False)

    # label
    if binary:
        label = np.load(path+"/label_bi.npy")  # (n,1)
    else:
        label = np.load(path+"/label_mul.npy")

    # mapping function from node ip to node id
    node_map = {}
    for i, node in enumerate(nodes):
        node_map[node] = i

    # adjacency adj: edge -> (node1, node2); adj_lists: {node: edge1, ..., edgen}
    # ['59.166.0.0:1390', '149.171.126.6:53'],
    adj = np.load(path+"/adj.npy", allow_pickle=True)
    adj_lists = defaultdict(set)
    for i, line in enumerate(adj):
        node1 = node_map[line[0]]
        node2 = node_map[line[1]]
        adj_lists[node1].add(i)  # mutual neighbor
        adj_lists[node2].add(i)

    # Define two layer aggregators and encoders
    # 编码器（enc1 和 enc2）和对应需要的聚合器（agg1 和 agg2）
    agg1 = MeanAggregator(edge_features, gcn=False, cuda=False)
    enc1 = Encoder(node_features, edge_feat.shape[1], 64, adj_lists,
                   agg1, num_sample=8, gcn=True, cuda=False)
    agg2 = MeanAggregator(edge_features, gcn=False, cuda=False)
    enc2 = Encoder(lambda nodes: enc1(nodes).t(), edge_feat.shape[1], 64,
                   adj_lists, agg2, num_sample=8, base_model=enc1, gcn=True, cuda=False)

    return enc2, edge_feat, label, node_map, adj