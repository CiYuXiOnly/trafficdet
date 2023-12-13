import torch
import torch.nn as nn
from torch.nn import init
import torch.nn.functional as F
from torch.autograd import Variable
import numpy as np
import random

'''
直接使用pytorch，而非dgl或pyG
1. 对节点进行k阶邻居采样，构成子图，每一阶中采样的数量固定（可能欠采样或重采样）
2. 聚合，即更新节点方式，比如平均
'''

class GraphSage(nn.Module):

    def __init__(self, num_classes, enc, edge_feat, node_map, adj):
        super(GraphSage, self).__init__()
        self.enc = enc # encoder
        self.edge_features = edge_feat
        self.node_map = node_map
        self.adj = adj # edges -> (node1, node2)
        self.xent = nn.CrossEntropyLoss()

        self.weight = nn.Parameter(torch.FloatTensor(num_classes, 2 * enc.embed_dim))
        init.xavier_uniform_(self.weight)

    def forward(self, edges):
        # GraphSAGE
        nodes = self.adj[edges]
        nodes = [set(x) for x in nodes]
        nodes = list(set.union(*nodes))
        nodes_id = [self.node_map[node] for node in nodes]

        # construct mapping from node_id to index
        unique_map = {}
        for idx, id in enumerate(nodes_id):
            unique_map[id] = idx

        node_embeds = self.enc(nodes_id).t().cpu().detach().numpy() # (N,e)  e: embed_dim
        
        # self.node_map[self.adj[edge][0]] 和 self.node_map[self.adj[edge][1]] 获取边两端节点的 ID
        # 转换为节点 index
        # 根据节点index获取节点嵌入向量
        # 连接节点嵌入向量，作为边嵌入向量
        edge_embeds = np.array([np.concatenate(
                (node_embeds[unique_map[self.node_map[self.adj[edge][0]]]],
                    node_embeds[unique_map[self.node_map[self.adj[edge][1]]]])) for edge in edges])
        edge_embeds = torch.FloatTensor(edge_embeds)
        scores = self.weight.mm(edge_embeds.t()) # W * embed: (c,2e) * (2e,E)  --> (c,E)  c : num of classes
        return scores.t(), edge_embeds  # (c,E) -->(E,c)

    def loss(self, edges, labels):
        scores, _ = self.forward(edges)
        return self.xent(scores, labels.squeeze())


class MeanAggregator(nn.Module):
    """
    聚合器，encoder根据聚合器的来更新节点embedding
    Aggregates a node's embeddings using mean of neighboring edges' embeddings
    """

    def __init__(self, edge_features, cuda=False, gcn=False):
        """
        Initializes the aggregator for a specific graph.

        edge_features -- function mapping LongTensor of edge ids to FloatTensor of feature values.
        cuda -- whether to use GPU
        gcn --- whether to perform concatenation GraphSAGE-style, or add self-loops GCN-style, 是否全局聚合
        """

        super(MeanAggregator, self).__init__()

        self.edge_features = edge_features
        self.cuda = cuda
        self.gcn = gcn

    def forward(self, nodes, to_neighs, num_sample=None):
        """
        nodes --- list of nodes in a batch
        to_neighs --- list of sets, each set is the set of neighbor edges for node in batch
        num_sample --- number of neighbors to sample. No sampling if None.
        """

        _set = set  # Local pointers to functions (speed hack)
        if num_sample is not None:
            _sample = random.sample
            samp_neighs = [
                _set(_sample(
                    to_neigh,
                    num_sample,
                )) if len(to_neigh) >= num_sample else to_neigh
                for to_neigh in to_neighs
            ]  # sample = neighbor, if neighboorhood size is less than num_sample
        else:
            samp_neighs = to_neighs

        if self.gcn:  # gcn=True, add self node into neighbor
            samp_neighs = [
                samp_neigh.union(set([nodes[i]]))
                for i, samp_neigh in enumerate(samp_neighs)
            ]

        unique_edges_list = list(set.union(*samp_neighs))
        unique_edges = {n: i for i, n in enumerate(unique_edges_list)}
        mask = Variable(torch.zeros(len(samp_neighs), len(unique_edges)))
        column_indices = [
            unique_edges[n] for samp_neigh in samp_neighs for n in samp_neigh
        ]

        row_indices = [
            i for i in range(len(samp_neighs))
            for j in range(len(samp_neighs[i]))
        ]

        mask[row_indices, column_indices] = 1

        if self.cuda:
            mask = mask.cuda()

        num_neigh = mask.sum(1, keepdim=True)  # torch.sum()  (n,m) --> (n, 1)
        mask = mask.div(num_neigh)  # normalization

        if self.cuda:
            embed_matrix = self.edge_features(
                torch.LongTensor(unique_edges_list).cuda())
        else:
            embed_matrix = self.edge_features(torch.LongTensor(unique_edges_list))
        to_feats = mask.mm(embed_matrix)
        return to_feats


class Encoder(nn.Module):
    """
    Encodes a node's using 'convolutional' GraphSage approach
    """
    def __init__(self,
                 node_features,
                 feature_dim,
                 embed_dim,
                 adj_lists,
                 aggregator,
                 num_sample=None,
                 base_model=None,
                 gcn=False,
                 cuda=False):
        super(Encoder, self).__init__()

        self.node_features = node_features
        self.feat_dim = feature_dim
        self.adj_lists = adj_lists
        self.aggregator = aggregator
        self.num_sample = num_sample
        if base_model != None:
            self.base_model = base_model

        self.gcn = gcn  # True: Mean-agg  False: GCN-agg
        self.embed_dim = embed_dim
        self.cuda = cuda
        self.aggregator.cuda = cuda
        self.weight = nn.Parameter(
            torch.FloatTensor(
                embed_dim, self.feat_dim + self.embed_dim if self.gcn else self.feat_dim
            )  # Mean-agg: [embed_dim,feat_dim] ; GCN-agg: [embed_dim, 2*feat_dim]
        )
        init.xavier_uniform_(self.weight)


    def forward(self, nodes):
        """
        Generates embeddings for a batch of nodes.
        nodes     -- list of nodes
        """
        neigh_feats = self.aggregator.forward(nodes, [self.adj_lists[int(node)] for node in nodes],
                                              self.num_sample)  # (nodes，neighbor edges，num samples)
        if self.gcn:
            if self.cuda:
                self_feats = self.node_features(torch.LongTensor(nodes).cuda())
            else:
                self_feats = self.node_features(torch.LongTensor(nodes)) # (n , f) n : num of nodes
            neigh_feats[torch.isnan(neigh_feats)] = 1e-2
            combined = torch.cat([self_feats, neigh_feats], dim=1)  # (n , 2f)
        else:
            combined = neigh_feats
        combined = self.weight.matmul(combined.t())
        combined = F.relu(combined) # relu W* F^T : (e, 2f) * (2f, n)  --> (e,n)  e: embed_dim
        return combined
