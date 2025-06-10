import os

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

from multiprocessing import Pool
import json
import numpy as np

from models.SAFE.asm_embedding.FunctionNormalizer import FunctionNormalizer
from models.SAFE.asm_embedding.InstructionsConverter import InstructionsConverter
from models.SAFE.neural_network.SAFEEmbedder import SAFEEmbedder
import models.SAFE.asm_embedding.instructions_filter as instructions_filter

from utils.utils import save_target_embd

import tensorflow as tf

from sklearn.metrics.pairwise import cosine_similarity
from utils.utils import tf_cosine_similarity

tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)

import logging

logging.getLogger("tensorflow").setLevel(logging.ERROR)

import time

ROOT_PATH = "/app/vol/"
SAFE_PATH = ROOT_PATH + "models/SAFE/"


class SAFE:

    def __init__(self, model, arch="x86"):
        self.converter = InstructionsConverter(SAFE_PATH + "data/i2v/word2id.json")
        self.normalizer = FunctionNormalizer(max_instruction=150)
        self.embedder = SAFEEmbedder(model)
        self.embedder.loadmodel()
        self.embedder.get_tensor()

        self.arch = arch

    def calculate_embedding(self, instructions_list, is_stat, detailed_logger):
        converted_instructions = self.converter.convert_to_ids(instructions_list)
        instructions, length = self.normalizer.normalize_functions([converted_instructions])

        embedding = self.embedder.embedd(instructions, length)

        return embedding


def initialize_model():
    model_path = "./data/safe.pb"
    safe = SAFE(SAFE_PATH + model_path)
    return model_path, safe


model_path, safe = initialize_model()


def calculate_similarity(source_cfg, target_cfg, target_json, is_stat=False, detailed_logger=None):
    source_instructions = instructions_filter.filter_instructions(source_cfg)
    target_instructions = instructions_filter.filter_instructions(target_cfg)

    source_embd = safe.calculate_embedding([source_instructions], is_stat, detailed_logger)
    target_embd = safe.calculate_embedding([target_instructions], is_stat, detailed_logger)

    if target_json is not None:
        save_target_embd(target_embd[0].tolist(), target_json)

    sim = cosine_similarity(source_embd, target_embd)

    return sim[0][0]


def calculate_similarity_batch(cfg_sources, target_json, pool, target_cfg=None, is_stat=False, detailed_logger=None):
    if target_cfg is None:
        with open(target_json) as json_file:
            json_decoded = json.load(json_file)

        target_embd = np.array(json_decoded['embedding'])
    else:
        target_instructions = instructions_filter.filter_instructions(target_cfg)
        target_embd = safe.calculate_embedding([target_instructions], is_stat, detailed_logger)[0]

    start = time.perf_counter()
    filtered_cfgs = []
    if pool is None:
        for cfg in cfg_sources:
            filtered_cfgs.append(instructions_filter.parallel_filter_instructions(cfg))
    else:
        filtered_cfgs = pool.map(instructions_filter.parallel_filter_instructions, cfg_sources, chunksize=40)
    end = time.perf_counter()
    detailed_logger.info(f"[SAFE] Filter functions: {end - start}")

    start_emb = time.perf_counter()
    source_embs = safe.calculate_embedding(filtered_cfgs, is_stat, detailed_logger)

    tf_matrix = tf.constant(source_embs, name="embeddings_matrix", dtype=tf.float32)
    tf_vec = tf.constant(target_embd, name="target_emb", dtype=tf.float32)

    sim_matrix = tf_cosine_similarity(tf_matrix, [tf_vec])

    end_emb = time.perf_counter()
    if is_stat:
        detailed_logger.info("[SAFE] Time to calculate COSSIM: " + str(end_emb - start_emb))

    with tf.compat.v1.Session() as sess:
        start_conv = time.perf_counter()
        numpy_embd = sess.run(sim_matrix)
        end_conv = time.perf_counter()
        # detailed_logger.info("[SAFE] Time to calculate convert matrix: " + str(end_conv - start_conv))
        sims_to_ret = numpy_embd[0].tolist()
        sess.close()

        return sims_to_ret


def calculate_similarity_pool(pool_embeddings, target_cfg, pool_json=None, num_variants=None):
    target_instructions = instructions_filter.filter_instructions(target_cfg)
    target_embd = safe.calculate_embedding([target_instructions], None, None)[0]

    if pool_embeddings is None:
        pool_embeddings = []
        for idx in range(num_variants):
            with open(f"{pool_json}_{idx}.json") as json_file:
                json_decoded = json.load(json_file)

            embd = np.array(json_decoded['embedding'])
            pool_embeddings.append(embd)
        pool_embeddings = np.array(pool_embeddings)
    else:
        pool_embeddings = np.array(pool_embeddings)

    tf_matrix = tf.constant(pool_embeddings, name="embeddings_matrix", dtype=tf.float32)
    tf_vec = tf.constant(target_embd, name="target_emb", dtype=tf.float32)

    sim_matrix = tf_cosine_similarity(tf_matrix, [tf_vec])

    with tf.compat.v1.Session() as sess:
        numpy_embd = sess.run(sim_matrix)
        sims_to_ret = numpy_embd[0].tolist()
        sess.close()

        return sims_to_ret


def calculate_embeddings(cfg_sources, pool=None, json_file=None):
    if pool is not None:
        filtered_cfgs = pool.map(instructions_filter.parallel_filter_instructions, cfg_sources)
    else:
        filtered_cfgs = []
        for cfg in cfg_sources:
            filtered_cfgs.append(instructions_filter.filter_instructions(cfg))

    embeddings = safe.calculate_embedding(filtered_cfgs, False, None)

    if json_file is not None:
        for idx, embd in enumerate(embeddings):
            save_target_embd(embd.tolist(), f"{json_file}_{idx}.json")

    return embeddings
