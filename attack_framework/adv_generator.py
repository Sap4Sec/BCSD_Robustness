import argparse
import pandas as pd
from tqdm import tqdm
import os
import pickle

from multiprocessing import Pool

import random

random.seed(10)

import gc

import time

from Config import Config
from Initializer import InitializerForQueryAttack

from StrandsEmbeddingSpace import StrandSpace

from utils.utils import get_test_csv, already_done, log_final, get_number_of_instructions

N_PROCESSES = 30


def load_model(model_name):
    print("LOAD MODEL")
    model = None
    if model_name == "SAFE":
        from models.SAFEModel import SAFEModelForQueryAttack
        model = SAFEModelForQueryAttack()
    elif model_name == "GEMINI":
        from models.GEMINIModel import GEMINIModelForQueryAttack
        model = GEMINIModelForQueryAttack()
    elif model_name == "GMN":
        from models.GMNModel import GMNModelForQueryAttack
        model = GMNModelForQueryAttack()
    elif model_name == "JTRANS":
        from models.JTRANSModel import JTRANSModelForQueryAttack
        model = JTRANSModelForQueryAttack()
    elif model_name == "PALMTREE":
        from models.PALMTREEModel import PALMTREEModelForQueryAttack
        model = PALMTREEModelForQueryAttack()
    elif model_name == "BINFINDER":
        from models.BINFINDERModel import BINFINDERModelForQueryAttack
        model = BINFINDERModelForQueryAttack()
    elif model_name == "TREX":
        from models.TREXModel import TREXModelForQueryAttack
        model = TREXModelForQueryAttack()
    elif model_name == "ZEEK":
        from models.ZEEKModel import ZEEKModelForQueryAttack
        model = ZEEKModelForQueryAttack()

    return model


def load_cfg(cfg_name):
    # Load the graph from the pickle file
    with open(cfg_name, 'rb') as file:
        loaded_graph = pickle.load(file)

    return loaded_graph


COMPILERS = ['gcc', 'clang']
OPTIMIZERS = ['O0', 'O3']


def perform_tests(conf, db_file):
    db = get_test_csv(db_file)

    done = already_done(conf.FINAL_STAT_NAME)
    print(f"Number of performed tests: {done}")

    final_stats_df = pd.read_csv(conf.FINAL_STAT_NAME)

    # Load BSCD model
    model = load_model(conf.MODEL)

    # Load strands embedding space
    embedding_matrix_filename = "embedding_matrix_definitive.pt"
    filtered_strands_df_filename = "definitive_strands.csv"
    ids_filename = "strands_ids_definitive.json"
    space = StrandSpace(embedding_matrix_filename, filtered_strands_df_filename, ids_filename)
    pool = Pool(processes=N_PROCESSES)

    pool_files = []
    for _, _, files in os.walk(conf.POOL_PATH):
        for file in files:
            if file.endswith(".pkl"):
                pool_files.append(file)

    if conf.SUB_SPLIT == 1:
        db = db[done:len(db) // 2]
    elif conf.SUB_SPLIT == 2:
        db = db[done + len(db) // 2: len(db)]

    # divide in split to speed up execution
    for el in tqdm(db):
        # Initialize test

        split_src = el['source_source'].split(":")
        source_c = split_src[0]
        func_line = int(split_src[1])
        source_object = f"x64-{el['source_compiler']}-{el['source_optimization']}/{el['source_project']}/{el['source_folder']}{el['source_object']}"
        source_function = el['source_function']
        source_gcc = el['source_cmd']

        target_object = f"x64-{el['target_compiler']}-{el['target_optimization']}/{el['target_project']}/{el['target_folder']}{el['target_object']}"
        target_function = el['target_function']

        query_variants = []

        for comp in COMPILERS:
            for opt in OPTIMIZERS:
                variant_file = f"x64-{comp}-{opt}_{el['target_object']}_{target_function}.pkl"
                variant_cfg = load_cfg(os.path.join(conf.POOL_PATH, variant_file))
                query_variants.append(variant_cfg)

        initializer = InitializerForQueryAttack(conf, model, source_object, source_function, query_variants,
                                                target_function)

        if initializer.initialize(conf):

            conf.DETAILED_LOGGER.warning(f"Initial similarity {initializer.get_initial_similarity()}")

            init_instrs = initializer.get_initial_number_of_instructions()
            init_nodes = initializer.get_initial_number_of_nodes()

            start_time = time.perf_counter()
            if conf.OPTIMIZER == "greedy":
                from GreedyQuery import GreedyQuery
                init_sim = initializer.get_initial_similarity()
                optimizer = GreedyQuery(initializer, conf, space)
                final_similarity, adv_example_cfg, applied_transformations = optimizer.execute_steps(pool)

                final_instrs = get_number_of_instructions(adv_example_cfg)
                final_nodes = adv_example_cfg.number_of_nodes()

                str_applied_actions = '-'.join(el for el in applied_transformations)

                # Delete target json file
                if optimizer and optimizer.model.target_embd:
                    for idx, _ in enumerate(initializer.target_variants):
                        os.remove(f"{optimizer.model.target_embd}_{idx}.json")
                del adv_example_cfg, optimizer, applied_transformations
            elif conf.OPTIMIZER == "random":
                from RandomBaseline import RandomBaseline
                init_sim = initializer.get_initial_similarity()

                seed = 10

                optimizer = RandomBaseline(initializer, conf, space, seed=seed)
                final_similarity, adv_example_cfg, applied_transformations = optimizer.execute_steps(pool)

                final_instrs = get_number_of_instructions(adv_example_cfg)
                final_nodes = adv_example_cfg.number_of_nodes()

                str_applied_actions = '-'.join(el for el in applied_transformations)

                # Delete target json file
                if optimizer and optimizer.model.target_embd:
                    for idx, _ in enumerate(initializer.target_variants):
                        os.remove(f"{optimizer.model.target_embd}_{idx}.json")
                del adv_example_cfg, optimizer, applied_transformations

            end_time = time.perf_counter()

            if conf.IS_STAT:

                # Save final results

                record = {
                    'source_object': source_object,  # .rsplit("/", 1)[1],
                    'source_function': source_function,
                    'source_c': source_c,
                    'source_func_line': func_line,
                    'source_gcc': source_gcc,
                    'target_object': target_object,  # .rsplit("/", 1)[1],
                    'target_function': target_function,
                    'num_initial_nodes': init_nodes,
                    'num_final_nodes': final_nodes,
                    'num_initial_instructions': init_instrs,
                    'num_final_instructions': final_instrs,
                    'transformation_type': str_applied_actions,
                    'total_time': end_time - start_time,
                    'iterations_folder': initializer.experiment_name,
                    'initial_similarity': init_sim,
                    'final_similarity': final_similarity
                }

                final_stats_df = pd.concat([final_stats_df, pd.DataFrame([record])])

                final_stats_df.to_csv(config.FINAL_STAT_NAME, index=False, mode='w')

                log_final(end_time - start_time, final_similarity, conf.DETAILED_LOGGER, conf.BRIEF_LOGGER)

            print(f"Final similarity {final_similarity}")
            print("---------------------------")

            del initializer
            gc.collect()

    close_pool(pool)


def close_pool(pool):
    pool.close()
    pool.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-m", "--model", dest="target_model",
                        help="choose between \{SAFE, GEMINI, GMN, BINFINDER, PALMTREE, JTRANS, TREX\}", required=True)
    parser.add_argument("-m2", "--model_2", dest="target_model_2",
                        help="choose between \{SAFE, GEMINI, GMN, BINFINDER, PALMTREE, JTRANS, TREX\}",
                        required=False, default=None)
    parser.add_argument("-d", "--data", dest="data_path",
                        help="path to binary dataset", required=False)
    parser.add_argument("-p", "--pool", dest="pool_path",
                        help="path to pool of functions", required=True)
    parser.add_argument("-dj", "--data_json", dest="data_json",
                        help="path to pairs dataset (json file)", required=True)
    parser.add_argument("-s", "--stat", dest="get_stats", action="store_true",
                        help="Store statistics in json file")
    parser.add_argument("--no-stats", dest="get_stats", action="store_false")
    parser.add_argument("-at", "--attack_type", dest="att_type", type=int,
                        help="choose between \{0 for TARGETED, 1 for UNTARGETED\}", required=True)
    parser.add_argument("-o", "--optimizer", dest="optimizer",
                        help="choose between \{greedy, random\}", required=False, default="greedy")
    parser.add_argument("-it", "--iterations", dest="iterations", type=int,
                        help="specify attack iterations", required=False, default=30)
    parser.add_argument("-pn", "--n_positions", dest="num_positions", type=int,
                        help="specify number of positions affected by transformations", required=False, default=100)
    parser.add_argument("-hpc", "--h_percentage", dest="heavy_percentage", type=int,
                        help="choose percentage of positions for heavy transformations", required=False,
                        default=20)
    parser.add_argument("-im", "--use_importance", dest="use_importance", action="store_true",
                        help="Use importance score")
    parser.add_argument("--no-im", dest="use_importance", action="store_false")
    parser.add_argument("-l", "--lambda", dest="lambda_factor", type=float,
                        help="specify scaling factor to limit perturbation size", required=False, default=0.0)
    parser.add_argument("-t", "--transformation", dest="transformation",
                        help="semantics-preserving transformation, choose between \{combo (all transformations), strandadd, dba, \
                            displace, swap\}", required=False, default="combo")
    parser.add_argument("-sp", "--split", dest="split",
                        help="choose between \{S1, S2, S3, S4\}", required=True)
    parser.add_argument("-ssp", "--sub_split", dest="sub_split",
                        help="choose between \{1, 2, 3, 4\}", type=int, default=1, required=False)

    args = parser.parse_args()

    print("##### RUN ATTACK ON #####")
    options = vars(args)
    for k in options:
        print(f"{k} -> {options[k]}")
    print("#########################")

    config = Config.get_default_config_for_query(args)

    perform_tests(config, args.data_json)
