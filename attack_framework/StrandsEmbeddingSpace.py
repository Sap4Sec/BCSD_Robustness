import torch

torch.set_num_threads(10)


import pandas as pd

import random
import json
import os


ROOT_PATH = "/app/vol/"

binbert_embs_folder = "binbert_embs/"

N_PROCESSES = 20

device = torch.device("cuda") if torch.cuda.is_available() else "cpu"


class StrandSpace:

    def __init__(self, embedding_matrix_filename, filtered_strands_df_filename, ids_filename):

        random.seed(10)

        self.strand2ids = json.load(open(os.path.join(ROOT_PATH, binbert_embs_folder, ids_filename), "r"))

        self.filtered_strands = pd.read_csv(os.path.join(ROOT_PATH, binbert_embs_folder,
                                                         filtered_strands_df_filename), sep='\t')
        self.filtered_strands = self.filtered_strands.where(pd.notnull(self.filtered_strands), None)

        self.embedding_matrix = torch.load(os.path.join(ROOT_PATH, binbert_embs_folder, embedding_matrix_filename))

        self.semnops_strands = self.filtered_strands.loc[(self.filtered_strands['radare_st'].apply(lambda x: len(json.loads(x)) == 1)) |
                                                         (self.filtered_strands['radare_st'].apply(lambda x: len(json.loads(x)) == 2))].to_dict(orient='records')

        self.embspace = EmbeddingSpace(self.embedding_matrix, self.strand2ids)

    def get_spreaded_strands(self, num_strands):
        sampled_ids = random.sample(self.strand2ids, num_strands)
        sampled = self.filtered_strands.loc[self.filtered_strands['strand_id'].isin(sampled_ids)]
        return sampled.to_dict(orient='records')

    def __get_unmasked_random(self, masked_neighbours_ids):

        random_neighs = self.filtered_strands.loc[self.filtered_strands['strand_id'].isin(masked_neighbours_ids)]

        return random_neighs.to_dict(orient='records')

    def get_neighbors(self, strand, topk=20, num_neighbours=10, keep_father=False):

        strand_id = strand['strand_id']
        masked_neighbours_ids, _ = self.embspace.find_top_k(strand_id, topk)

        unmasked_return = self.__get_unmasked_random(masked_neighbours_ids)

        if keep_father:
            result = random.sample(unmasked_return, num_neighbours-1) + [strand.to_dict()]
        else:
            result = random.sample(unmasked_return, num_neighbours)

        return result


class EmbeddingSpace:

    def __init__(self, embeddings_matrix, strand2id):
        self.embeddings_matrix = embeddings_matrix
        self.embeddings_matrix.to(device)
        self.strand2id = strand2id

    def find_top_k(self, id_to_query, k):
        res = []
        scores = []
        idx = self.strand2id.index(id_to_query)

        embedding_to_query = torch.clone(self.embeddings_matrix[idx]).to(device)

        embedding_to_query = torch.reshape(embedding_to_query, (1, -1)).to(device)
        embd_to_query_norm = embedding_to_query / embedding_to_query.norm(dim=1)[:, None]

        embd_matrix_norm = self.embeddings_matrix / self.embeddings_matrix.norm(dim=1)[:, None]

        dist = torch.mm(embd_to_query_norm, embd_matrix_norm.transpose(0, 1).to(device))
        dist = torch.reshape(dist, (-1, ))

        index_sorted = torch.argsort(dist, descending=True)
        top_k = index_sorted[:k]

        res.extend([self.strand2id[k] for k in top_k])
        scores.extend([dist[k].item() for k in top_k])

        return res, scores
