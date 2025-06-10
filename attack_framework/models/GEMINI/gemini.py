import os

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import time
import json
import tensorflow as tf
import networkx as nx
import numpy as np
from math import acos, pi
from sklearn.metrics.pairwise import cosine_similarity

tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)

import logging

logging.getLogger("tensorflow").setLevel(logging.ERROR)

from models.GEMINI.binary_similarity.GEMINIEmbedder import GEMINIEmbedder
import models.GEMINI.asm_embedding.instruction_filter as instruction_filter

from utils.utils import tf_cosine_similarity, save_target_embd

ROOT_PATH = "/app/vol/"
GEMINI_PATH = ROOT_PATH + "models/GEMINI/"


class GEMINI:

    def __init__(self, model, arch='x86'):

        self.embedder = GEMINIEmbedder(model)
        self.embedder.loadmodel()
        self.embedder.get_tensor()

        self.arch = arch

    def embeddCFG(self, cfg, is_stat, detailed_logger):
        pairs = []
        label = []
        cfg_nodes = []
        adj = nx.adjacency_matrix(cfg)

        is_stat = False
        if is_stat:
            start_fe = time.perf_counter()
        for n in cfg.nodes(data=True):
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
        pairs, _ = instruction_filter.padAndFilter(pairs, label, 150)
        graph1, graph2 = zip(*pairs)
        adj, nodes = zip(*graph1)
        if is_stat:
            end_fe = time.perf_counter()
            detailed_logger.info(f"[GEMINI] Time to extract adj and nodes: {end_fe - start_fe}")

            start_gemini = time.perf_counter()

        embedding = self.embedder.embedd(adj, nodes)

        if is_stat:
            end_gemini = time.perf_counter()
            detailed_logger.info(f"[GEMINI] Time to embedd: {end_gemini - start_gemini}")

        return embedding


def initialize_model():
    model_path = "./binary_similarity/checkpoints"
    gemini = GEMINI(GEMINI_PATH + model_path)
    return gemini


# Initialize model
gemini = initialize_model()


def calculate_similarity(source_cfg, source_str, target_cfg, target_str, target_json=None,
                         is_stat=False, detailed_logger=None):
    source_acfg = instruction_filter.extract_features(source_cfg, source_str)
    target_acfg = instruction_filter.extract_features(target_cfg, target_str)

    source_embd = gemini.embeddCFG(source_acfg, is_stat, detailed_logger)
    target_embd = gemini.embeddCFG(target_acfg, is_stat, detailed_logger)

    if target_json is not None:
        save_target_embd(target_embd[0].tolist(), target_json)

    cosim = cosine_similarity(source_embd, target_embd)
    if cosim > 1:
        return 1
    sim = 1 - (acos(cosim) / pi)
    return sim


def calculate_similarity_batch(cfg_sources, source_str, target_json, pool=None,
                               target_cfg=None, target_str=None, is_stat=False, detailed_logger=None):
    if target_cfg is None:
        with open(target_json) as json_file:
            json_decoded = json.load(json_file)

        target_embd = np.array(json_decoded['embedding'])
    else:
        target_acfg = instruction_filter.extract_features(target_cfg, target_str)
        target_embd = gemini.embeddCFG(target_acfg, is_stat, detailed_logger)[0]

    start = time.perf_counter()

    source_acfgs = []
    if pool is None:
        for cfg in cfg_sources:
            source_acfgs.append(instruction_filter.parallel_extract_features([cfg, source_str]))
    else:
        parameters = []
        if target_cfg is None:
            for cfg in cfg_sources:
                parameters.append([cfg, source_str])
        else:
            for i, cfg in enumerate(cfg_sources):
                parameters.append([cfg, source_str[i]])

        source_acfgs = pool.map(instruction_filter.parallel_extract_features, parameters)

    end = time.perf_counter()
    detailed_logger.info(f"[GEMINI] Extract features from acfgs: {end - start}")

    start_emb = time.perf_counter()
    source_embs = gemini.embedder.embedd(np.array([el[0] for el in source_acfgs]),
                                         np.array([el[1] for el in source_acfgs]))

    sims_to_ret = cosine_similarity(source_embs, target_embd.reshape(1, -1)).flatten().tolist()

    end_emb = time.perf_counter()

    if is_stat:
        detailed_logger.info(f"[GEMINI] Time to calculate COSSIM: {end_emb - start_emb}")

    for i, _ in enumerate(sims_to_ret):
        sims_to_ret[i] = 1 - (acos(sims_to_ret[i]) / pi) if sims_to_ret[i] < 1 else 1

    return sims_to_ret


def calculate_similarity_pool(pool_embeddings, target_cfg, target_strings, pool_json=None, num_variants=None):
    target_acfg = instruction_filter.extract_features(target_cfg, target_strings)
    target_embd = gemini.embeddCFG(target_acfg, None, None)[0]

    if pool_embeddings is None:
        pool_embeddings = []
        for idx in range(num_variants):
            with open(f"{pool_json}_{idx}.json") as json_file:
                json_decoded = json.load(json_file)

            embd = np.array(json_decoded['embedding'])
            pool_embeddings.append(embd)
        pool_embeddings = np.array(pool_embeddings)

    sims_to_ret = cosine_similarity(pool_embeddings, target_embd.reshape(1, -1)).flatten().tolist()

    for i, _ in enumerate(sims_to_ret):
        sims_to_ret[i] = 1 - (acos(sims_to_ret[i]) / pi) if sims_to_ret[i] < 1 else 1

    return sims_to_ret


def calculate_embeddings(source_cfgs, source_strings, pool=None, json_file=None):
    source_acfgs = []
    if pool is not None:
        parameters = []
        for cfg in source_cfgs:
            parameters.append([cfg, source_strings])
        source_acfgs = pool.map(instruction_filter.parallel_extract_features, parameters)
    else:
        for cfg in source_cfgs:
            source_acfgs.append(instruction_filter.parallel_extract_features([cfg, source_strings]))

    embeddings = gemini.embedder.embedd(np.array([el[0] for el in source_acfgs]),
                                        np.array([el[1] for el in source_acfgs]))

    if json_file is not None:
        for idx, embd in enumerate(embeddings):
            save_target_embd(embd.tolist(), f"{json_file}_{idx}.json")

    return embeddings
