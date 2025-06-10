import argparse

from multiprocessing import Pool

from Config import ConfigForPool
from Initializer import InitializerForPool

from utils.utils import already_done

import os
import pandas as pd
import pickle
import numpy as np

import random

random.seed(10)

import re

from tqdm import tqdm

import glob

from sklearn.metrics import accuracy_score

N_PROCESSES = 20

ROOT_PATH = "/app/vol"

COMPILERS = ['gcc', 'clang']
OPTIMIZERS = ['O0', 'O3']


def load_model(model_name):
    model = None
    if model_name == "SAFE":
        from models.SAFEModel import SAFEModelForPool
        model = SAFEModelForPool()
    elif model_name == "GEMINI":
        from models.GEMINIModel import GEMINIModelForPool
        model = GEMINIModelForPool()
    elif model_name == "GMN":
        from models.GMNModel import GMNModelForPool
        model = GMNModelForPool()
    elif model_name == "ASM2VEC":
        from models.ASM2VECModel import ASM2VECModel
        model = ASM2VECModel()
    elif model_name == "JTRANS":
        from models.JTRANSModel import JTRANSModelForPool
        model = JTRANSModelForPool()
    elif model_name == "PALMTREE":
        from models.PALMTREEModel import PALMTREEModelForPool
        model = PALMTREEModelForPool()
    elif model_name == "BINFINDER":
        from models.BINFINDERModel import BINFINDERModelForPool
        model = BINFINDERModelForPool()
    elif model_name == "TREX":
        from models.TREXModel import TREXModelForPool
        model = TREXModelForPool()

    return model


def load_cfg(cfg_name):
    # Load the graph from the pickle file
    with open(cfg_name, 'rb') as file:
        loaded_graph = pickle.load(file)

    return loaded_graph


def get_iter_row(res_df, att_type, th, iteration):
    if att_type == 'T':
        try:
            first_row = res_df[res_df.iter == iteration].iloc[0]
            check = True if first_row['iter_similarity'] >= th else False
        except:
            first_row = res_df.iloc[-1]
            check = True if first_row['iter_similarity'] >= th else False
    else:
        try:
            first_row = res_df[res_df.iter == iteration].iloc[0]
            check = False if first_row['iter_similarity'] <= th else True
        except:
            first_row = res_df.iloc[-1]
            check = False if first_row['iter_similarity'] <= th else True

    return first_row, check


def get_best_th_stat(stats_folder, att_type, th, cfg_folder, iteration):
    cfg_path = os.path.join(stats_folder, cfg_folder)

    pattern = os.path.join(cfg_path, f'*.csv')
    csv_files = glob.glob(pattern)

    csv_file = csv_files[0]

    ex_df = pd.read_csv(csv_file, skiprows=[1])

    if len(ex_df.index) > 0:
        best_iter_stats, check = get_iter_row(ex_df, att_type[0], th, iteration)

        return best_iter_stats, check

    return None, None


def perform_function_search(conf):
    att_type = "TARGETED" if args.att_type == 0 else "UNTARGETED"

    stats_df = pd.read_csv(conf.FINAL_STAT_NAME, skiprows=[1]).to_dict(orient='records')

    done = already_done(f"{config.FINAL_FS_STAT_NAME}_{1}.csv")
    if done != 0:
        done += 2

    print(f"DONE in {config.FINAL_FS_STAT_NAME}_{1}: {done}")

    model = load_model(conf.MODEL)

    pool = Pool(processes=N_PROCESSES)

    # Load pool for function search
    pool_path = conf.POOL_PATH

    pool_files = []
    for _, _, files in os.walk(pool_path):
        for file in files:
            if file.endswith(".pkl"):
                pool_files.append(file)

    funcs_from_pool = random.sample(pool_files, conf.POOL_SIZE)

    functions_pool, func_obj_pairs = {}, []
    for file in funcs_from_pool:
        loaded_cfg = load_cfg(os.path.join(pool_path, file))
        functions_pool[file] = loaded_cfg

        comp_opt_pair = file.split("_", 1)[0]
        func_name = loaded_cfg['name']
        obj_name = loaded_cfg['filename'].replace("/app/DB/builds/", "").split("/", 1)[1]

        func_obj_pairs.append((comp_opt_pair, func_name, obj_name))

    print(f'LEN POOL: {len(functions_pool)}')

    # calculate pool embeddings (GMN excluded)
    if conf.MODEL != 'GMN':
        pool_embeddings = model.calculate_pool_embeddings(list(functions_pool.values()), pool)
        pool_embeddings = dict(zip(functions_pool.keys(), pool_embeddings))
    else:
        pool_embeddings = None

    print(len(stats_df))

    for record in tqdm(stats_df[done:]):

        iterations_folder = os.path.join(conf.FINAL_CFG_PATH, record['iterations_folder'])

        pkl_list = [file for file in os.listdir(iterations_folder) if file.endswith('.pkl')]
        iter_nums = [int(re.search(r'_ITER(\d+)', filename).group(1)) for filename in pkl_list]
        success_iter = max(iter_nums)

        cfg_name = [filename for filename in pkl_list if f'_ITER{success_iter}' in filename][0]
        cfg_name = os.path.join(iterations_folder, cfg_name)

        adv_cfg = load_cfg(cfg_name)

        # calculate the similarity between the adversarial example and the functions in the pool
        # then output the K functions in the pool more similar to the adversarial example

        source_object = record['source_object']  # it has the same representation of the dict keys
        source_function = record['source_function']
        source_c = record['source_c']
        source_func_line = record['source_func_line']
        source_gcc = record['source_gcc']

        target_object = record['target_object']
        target_function = record['target_function']

        initial_similarity = record['initial_similarity']
        final_similarity = record['final_similarity']

        # load the variants
        variants_not_in_pool, all_variants = {}, []
        for comp in COMPILERS:
            for opt in OPTIMIZERS:
                variant_file = f"x64-{comp}-{opt}_{target_object.rsplit('/', 1)[1]}_{target_function}.pkl"
                if (f"x64-{comp}-{opt}", target_function, target_object.split('/', 1)[1]) not in func_obj_pairs:
                    variant_cfg = load_cfg(os.path.join(conf.POOL_PATH, variant_file))
                    variants_not_in_pool[variant_file] = variant_cfg
                all_variants.append(variant_file)

        # calculate variant embeddings
        if conf.MODEL != "GMN":
            variants_not_in_pool_embeddings = model.calculate_pool_embeddings(list(variants_not_in_pool.values()), pool)
            variant_embeddings = dict(zip(variants_not_in_pool.keys(), variants_not_in_pool_embeddings))
            for v_file in all_variants:
                if v_file not in variant_embeddings.keys():
                    variant_embeddings[v_file] = pool_embeddings[v_file]
        else:
            variant_embeddings = dict(zip(variants_not_in_pool.keys(), list(variants_not_in_pool.values())))
            for v_file in all_variants:
                if v_file not in variant_embeddings:
                    variant_embeddings[v_file] = functions_pool[v_file]

        # load pool subset according to the top

        # delete possible variants that are in the pool
        pool_without_variants = set(functions_pool.keys()) - set(variant_embeddings.keys())

        # select randomly functions to fill the pool
        pool_subset_files = random.sample(pool_without_variants, len(funcs_from_pool) - len(all_variants))

        if conf.MODEL != "GMN":
            pool_subset_embeddings = [pool_embeddings[el] for el in pool_subset_files]
            pool_subset_embeddings.extend(variant_embeddings.values())
        else:
            pool_subset_embeddings = None
        pool_subset_cfgs = [functions_pool[el] for el in pool_subset_files]
        pool_subset_cfgs.extend(variant_embeddings.values())

        pool_subset_files.extend(variant_embeddings.keys())

        initializer = InitializerForPool(conf, model, pool_subset_embeddings, source_object, source_function,
                                         target_cfg=adv_cfg, function_pool=pool_subset_cfgs)

        if initializer.initialize_for_pool(conf):

            if model.name != "GMN":
                adv_pool_similarities = initializer.model.evaluate_batch()
            else:
                # pool here is the pool of processes for multiprocessing
                adv_pool_similarities = initializer.model.evaluate_batch(pool)

            adv_sims_dict = dict(zip(pool_subset_files, adv_pool_similarities))
            sorted_adv_sims_dict = dict(sorted(adv_sims_dict.items(), key=lambda item: item[1], reverse=True))

            # calculate success condition on clean data (for clean performance of the model)
            clean_initializer = InitializerForPool(conf, model, pool_subset_embeddings, source_object, source_function,
                                                   function_pool=pool_subset_cfgs)

            clean_initializer.initialize_for_pool(conf)
            if model.name != "GMN":
                clean_pool_similarities = clean_initializer.model.evaluate_batch()
            else:
                # pool here is the pool of processes for multiprocessing
                clean_pool_similarities = clean_initializer.model.evaluate_batch(pool)

            clean_sims_dict = dict(zip(pool_subset_files, clean_pool_similarities))
            sorted_clean_sims_dict = dict(sorted(clean_sims_dict.items(), key=lambda item: item[1], reverse=True))

            for k in range(1, conf.SEARCH_DEPTH + 1):
                final_fs_stat_name = f"{config.FINAL_FS_STAT_NAME}_{k}.csv"

                header = True if not os.path.exists(final_fs_stat_name) else False

                # Sort adv similarities and consider top-K
                top_k = list(sorted_adv_sims_dict.keys())[:k]
                adv_k_th = sorted_adv_sims_dict[top_k[-1]]

                count_vars = 0
                for el in all_variants:
                    if el in top_k:
                        count_vars += 1

                # check success condition
                if att_type == "TARGETED":
                    arate_1 = True if count_vars >= 1 else False
                    arate_2 = True if count_vars >= 2 else False
                    arate_3 = True if count_vars >= 3 else False
                    arate_4 = True if count_vars >= 4 else False

                    if (arate_4 == True and arate_3 == False) or (arate_4 == True and arate_2 == False):
                        print("ERROR IN ARATE CALCULATION")

                else:
                    arate_1 = True if count_vars < 4 else False
                    arate_2 = True if count_vars < 3 else False
                    arate_3 = True if count_vars < 2 else False
                    arate_4 = True if count_vars < 1 else False

                # Sort initial similarities and consider top-K
                top_k = list(sorted_clean_sims_dict.keys())[:k]

                count_vars = 0
                for el in all_variants:
                    if el in top_k:
                        count_vars += 1

                # check success condition
                if att_type == "TARGETED":
                    clean_1 = True if count_vars >= 1 else False
                    clean_2 = True if count_vars >= 2 else False
                    clean_3 = True if count_vars >= 3 else False
                    clean_4 = True if count_vars >= 4 else False
                else:
                    clean_1 = True if count_vars < 4 else False
                    clean_2 = True if count_vars < 3 else False
                    clean_3 = True if count_vars < 2 else False
                    clean_4 = True if count_vars < 1 else False

                gt = 'False' if att_type == "TARGETED" else 'True'

                fs_record = {
                    'source_object': source_object,
                    'source_function': source_function,
                    'source_c': source_c,
                    'source_func_line': source_func_line,
                    'source_gcc': source_gcc,
                    'target_object': target_object,
                    'target_function': target_function,
                    'clean_similarity': initial_similarity,
                    'adv_similarity': final_similarity,
                    'k_th': adv_k_th,
                    'gt': gt,
                    'arate@1': arate_1,
                    'arate@2': arate_2,
                    'arate@3': arate_3,
                    'arate@4': arate_4,
                    'clean@1': clean_1,
                    'clean@2': clean_2,
                    'clean@3': clean_3,
                    'clean@4': clean_4,
                    'iterations_folder': record['iterations_folder']
                }

                df_to_write = pd.DataFrame([fs_record])

                df_to_write.to_csv(final_fs_stat_name,
                                   header=header,
                                   index=False, mode='a')

    close_pool(pool)


def get_mod_size(row, iter_folder, att_type):
    iterations_folder = os.path.join(iter_folder, row['iterations_folder'])

    csv_file = [f for f in os.listdir(iterations_folder) if f.endswith('.csv')][0]
    csv_file = os.path.join(iterations_folder, csv_file)

    iters_df = pd.read_csv(csv_file, skiprows=[1])

    iter_row = iters_df.iloc[-1]
    instr_mod_size = iter_row['num_iter_instructions'] - iter_row['num_initial_instructions']
    node_mod_size = iter_row['num_iter_nodes'] - iter_row['num_initial_nodes']

    return pd.Series(
        [instr_mod_size, node_mod_size, iter_row['num_initial_instructions'], iter_row['num_iter_instructions'],
         iter_row['best_iter']])


def apply_modification_size(stats_query_folder, stats_df, att_type):
    stats_df[['instrs_m_size', 'nodes_m_size', 'init_instrs', 'final_instrs', 'best_iter']] = stats_df.apply(
        get_mod_size, axis=1, args=(stats_query_folder, att_type,))

    return stats_df


penalties = {'arate@1': 0.25, 'arate@2': 0.50, 'arate@3': 0.75, 'arate@4': 1}


def get_concat_df(conf):
    pd_dfs = []

    root_folder = ""
    if conf.SPLIT is None:
        subdirectories = [subdir for subdir in os.listdir(conf.BASE_FS_STAT_PATH)]
    else:
        subdirectories = [subdir for subdir in os.listdir(conf.BASE_FS_STAT_PATH) if
                          os.path.isdir(os.path.join(conf.BASE_FS_STAT_PATH, subdir)) and conf.SPLIT in subdir]

    for subdir in subdirectories:

        subdir_path = os.path.join(conf.BASE_FS_STAT_PATH, subdir)

        subsubdirectories = [_subdir for _subdir in os.listdir(subdir_path) if
                             os.path.isdir(os.path.join(subdir_path, _subdir))]

        for ssdir in subsubdirectories:
            ssdir_path = os.path.join(subdir_path, ssdir)

            pattern = os.path.join(ssdir_path, f'*_{conf.SEARCH_DEPTH}.csv')

            csv_files = glob.glob(pattern)

            for csv_f in csv_files:
                stats_df = pd.read_csv(csv_f)

                pd_dfs.append(stats_df)

    concat_df = pd.concat(pd_dfs)

    print(len(concat_df.index))

    return concat_df


def get_stats_fs(concat_df, stat_type="adv", att_type=0):
    print(f"NUM OF EXPERIMENTS: {len(concat_df.index)}")

    if stat_type == "adv":
        accuracies = []
        m_sizes = []
        for i in range(1, 5):
            arate_i = concat_df.loc[concat_df[f'arate@{i}'] == True]
            accuracies.append(round((len(arate_i.index) / len(concat_df.index)) * 100, 2))
        return accuracies, m_sizes
    elif stat_type == "adv_for_m":
        init_m_sizes = []
        final_m_sizes = []
        for i in range(1, 5):
            arate_i = concat_df.loc[concat_df[f'arate@{i}'] == True]
            init_m_sizes.append(
                [round(np.average(arate_i['init_instrs']), 2), round(np.std(arate_i['init_instrs']), 2)])
            final_m_sizes.append(
                [round(np.average(arate_i['final_instrs']), 2), round(np.std(arate_i['final_instrs']), 2)])
        return init_m_sizes, final_m_sizes
    elif stat_type == "best_iter":
        return round(np.average(concat_df['best_iter']), 2)
    elif stat_type == "clean":
        accuracies = []
        gt_flag = True if att_type == 0 else False
        for i in range(1, 5):
            init_i = concat_df.loc[concat_df[f'clean@{i}'] == gt_flag]
            accuracies.append(round((len(init_i.index) / len(concat_df.index)) * 100, 2))
        return accuracies
    elif stat_type == "w_adv":
        arates_columns = ['arate@1', 'arate@2', 'arate@3', 'arate@4']
        concat_df['last_true'] = concat_df[arates_columns].apply(lambda row: row[::-1].idxmax() if row.any() else False,
                                                                 axis=1)
        concat_df['wrate'] = concat_df.apply(
            lambda row: False if row['last_true'] is False else penalties[row['last_true']] * row[row['last_true']],
            axis=1
        )
        accuracies = round((concat_df['wrate'].sum() / len(concat_df.index)) * 100,
                           2)
        print("---------------------")

        return accuracies

    return None


def close_pool(pool):
    pool.close()
    pool.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-m", "--model", dest="target_model",
                        help="choose between \{GEMINI, GMN, BINFINDER, SAFE, JTRANS, TREX, PALMTREE\}", required=True)
    parser.add_argument("-d", "--data", dest="data_path",
                        help="path to binary dataset", required=True)
    parser.add_argument("-p", "--pool", dest="pool_path",
                        help="path to pool dataset", required=True)
    parser.add_argument("-at", "--attack_type", dest="att_type", type=int,
                        help="choose between \{0 for TARGETED, 1 for UNTARGETED\}", required=True)
    parser.add_argument("-o", "--optimizer", dest="optimizer",
                        help="choose between \{greedy, BS\}", required=False, default="greedy")
    parser.add_argument("-it", "--iterations", dest="iterations", type=int,
                        help="specify attack iterations", required=False, default=30)
    parser.add_argument("-l", "--lambda", dest="lambda_factor", type=float,
                        help="specify scaling factor to limit perturbation size", required=False, default=0.002)
    parser.add_argument("-pn", "--n_positions", dest="num_positions", type=int,
                        help="choose number of positions involved in transformations", required=False,
                        default=200)
    parser.add_argument("-hpc", "--h_percentage", dest="heavy_percentage", type=int,
                        help="choose percentage of positions for heavy transformations", required=False,
                        default=20)
    parser.add_argument("-im", "--use_importance", dest="use_importance", action="store_true",
                        help="Use importance score")
    parser.add_argument("--no-im", dest="use_importance", action="store_false")
    parser.add_argument("-t", "--transformation", dest="transformation",
                        help="semantics-preserving transformation, choose between \{combo (all transformations), strandadd, dba, \
                            displace, swap\}",
                        required=False, default="combo")
    parser.add_argument("-sp", "--split", dest="split",
                        help="choose between \{S1, S2, S3, S4}", required=True)
    parser.add_argument("-ssp", "--sub_split", dest="sub_split",
                        help="choose between {1, 2, 3, 4}", type=int, default=1, required=False)
    parser.add_argument("-k", "--sdepth", dest="search_depth",
                        help="search depth", type=int, default=10, required=False)
    parser.add_argument("-ps", "--pool_size", dest="pool_size",
                        help="pool size", type=int, default=100, required=False)
    parser.add_argument("-ts", "--task", dest="task",
                        help="0 for function search, 1 for stats on function search", type=int, default=0,
                        required=False)

    args = parser.parse_args()

    print("##### RUN ATTACK ON #####")
    options = vars(args)
    for k in options:
        print(f"{k} -> {options[k]}")
    print("#########################")

    config = ConfigForPool.get_config_for_pool(args)

    if args.task == 0:
        perform_function_search(config)
    else:
        config.SPLIT = None
        concat_df = get_concat_df(config)

        adv_perc = get_stats_fs(concat_df, stat_type="adv", att_type=config.ATT_TYPE)
        # print("ADV ACC: {:0.2f}".format(adv_perc))
        print(f"A-rates: {adv_perc[0]}")
        print(f"M-sizes [INSTRS, NODES]: {adv_perc[1]}")

        clean_perc = get_stats_fs(concat_df, stat_type="clean", att_type=config.ATT_TYPE)
        print(f"Clean accs: {clean_perc}")

        weighted_perc = get_stats_fs(concat_df, stat_type="w_adv", att_type=config.ATT_TYPE)
        print(f"Weighted a-rate: {weighted_perc}")
