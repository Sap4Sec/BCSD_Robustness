import sys
import uuid

import numpy as np

import os

import time

import copy

import pickle

import logging

sys.path.append('../')

from utils.utils import clear_folder, print_config, StateSave, StateSave_2_models
from transformations.semnops import get_combo_nops, get_atomic_nops

# from CFGExtractor.FunctionAnalyzerRadare import RadareFunctionAnalyzer
from CFGExtractor.Extractor import Extractor

'''
def get_cfg(filename, function_name):
    # Get CFG
    analyzer = RadareFunctionAnalyzer(filename, function_name, use_symbol=True)
    functions = analyzer.analyze()

    for function in functions:
        if function_name in function:
            analyzer.r2.quit()
            return functions[function]

    analyzer.r2.quit()
    return None
'''

ROOT_PATH = '/app/vol'
libc = os.path.join(ROOT_PATH, "CFGExtractor/data/libc_signatures.json")


class Initializer:

    def __init__(self, conf, model, source_object, source_function, target_obj, target_function):

        self.path = conf.DATA_PATH
        self.source_object = source_object
        self.source_function = source_function
        self.target_object = target_obj
        self.target_function = target_function

        self.r2_source = None
        self.r2_target = None

        self.model = model
        self.init_similarity = 0

        self.state_save = None
        self.experiment_name = None

        self.brief_logger = None
        self.detailed_logger = None

    @staticmethod
    def get_entry_points(cfg):
        entry_points = []
        for n in cfg.nodes(data=True):
            n_ep = n[1]['entry_point']
            entry_points.append(n_ep)

        return entry_points

    def initialize(self, conf, target_path=None, use_angr=False, updated_cfg=None):

        use_angr = True if (conf.MODEL == "PALMTREE" or use_angr == True) else False

        # Get CFG for source and target
        # self.r2_source = get_cfg(self.path + self.source_object, self.source_function)
        start = time.perf_counter()

        r2_source_extractor = Extractor(os.path.join(self.path, self.source_object), self.source_function, libc,
                                        use_angr=use_angr)
        self.r2_source = r2_source_extractor.extract_func_cfg(use_angr=use_angr)

        if updated_cfg is not None:
            self.r2_source['cfg'] = updated_cfg

        target_root_path = target_path if target_path is not None else self.path
        # self.r2_target = get_cfg(self.path + self.target_object, self.target_function)
        r2_target_extractor = Extractor(os.path.join(target_root_path, self.target_object), self.target_function, libc,
                                        use_angr=use_angr)
        self.r2_target = r2_target_extractor.extract_func_cfg(use_angr=use_angr)

        end = time.perf_counter()
        # print(f"[INITIALIZER] Extract CFGs: {end-start}")

        if conf.IS_STAT:
            self.brief_logger = copy.deepcopy(conf.BRIEF_LOGGER)
            self.detailed_logger = copy.deepcopy(conf.DETAILED_LOGGER)

            print_config(self.brief_logger, self.detailed_logger, conf.MODEL,
                         self.source_object.rsplit("/", 1)[1], self.source_function,
                         self.target_object.rsplit("/", 1)[1], self.target_function)

        if conf.MODEL == "SAFE":
            self.model.initialize_model("SAFE", self.r2_source, self.r2_target, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)

        elif conf.MODEL == "GEMINI":
            self.model.initialize_model("GEMINI", self.r2_source, self.r2_target, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "GMN":
            self.model.initialize_model("GMN", self.r2_source, self.r2_target, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
        elif conf.MODEL == "ASM2VEC":
            self.model.initialize_model("ASM2VEC", self.r2_source, self.r2_target, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "JTRANS":
            self.model.initialize_model("JTRANS", self.r2_source, self.r2_target, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "BINBERT":
            self.model.initialize_model("BINBERT", self.r2_source, self.r2_target, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "PALMTREE":
            self.model.initialize_model("PALMTREE", self.r2_source, self.r2_target, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "BINFINDER":
            self.model.initialize_model("BINFINDER", self.r2_source, self.r2_target, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "TREX":
            self.model.initialize_model("TREX", self.r2_source, self.r2_target, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)

        self.init_similarity = self.model.evaluate()

        if conf.IS_STAT:
            self.experiment_name = uuid.uuid4()
            experiment_path = f"{conf.FINAL_CFG_PATH}/{self.experiment_name}/"

            self.state_save = StateSave(experiment_path, stats_name=uuid.uuid4(), cfg_name=uuid.uuid4(),
                                        initial_similarity=self.init_similarity,
                                        num_initial_nodes=self.get_initial_number_of_nodes(),
                                        num_initial_instrs=self.get_initial_number_of_instructions())

            self.detailed_logger.info("[Main] Initial similarity: {}".format(self.init_similarity))
            self.brief_logger.info("[Main] Initial similarity: {}".format(self.init_similarity))

        return True

    def get_initial_similarity(self):
        return self.init_similarity

    def get_initial_number_of_nodes(self):
        return self.r2_source['cfg'].number_of_nodes()

    def get_target_numer_of_nodes(self):
        return self.r2_target['cfg'].number_of_nodes()

    def get_initial_number_of_instructions(self):

        count = 0
        for n in self.r2_source['cfg'].nodes(data=True):
            count += len(n[1]['disasm'])

        return count

    def get_target_number_of_instructions(self):

        count = 0
        for n in self.r2_target['cfg'].nodes(data=True):
            count += len(n[1]['disasm'])

        return count

    # use when combining multiple attacks
    def set_r2_source(self, source_cfg):
        self.r2_source['cfg'] = source_cfg

    # use when combining multiple attacks
    def set_initial_similarity(self, sim):
        self.init_similarity = sim


class InitializerForQueryAttack:

    def __init__(self, conf, model, source_object, source_function, target_variants, target_function):

        self.path = conf.DATA_PATH

        self.source_object = source_object
        self.source_function = source_function

        self.target_function = target_function
        self.target_variants = target_variants

        self.model = model
        self.init_similarity = 0
        self.init_variant = 0

        self.state_save = None
        self.experiment_name = None

        self.brief_logger = logging.getLogger("brief")
        self.detailed_logger = logging.getLogger("detailed")

    def initialize(self, conf):

        use_angr = True if conf.MODEL == "PALMTREE" else False

        # Get CFG for source and target
        # self.r2_source = get_cfg(self.path + self.source_object, self.source_function)
        r2_source_extractor = Extractor(os.path.join(self.path, self.source_object),
                                        self.source_function, libc, use_angr=use_angr)
        self.r2_source = r2_source_extractor.extract_func_cfg(use_angr=use_angr)

        # self.brief_logger = logging.getLogger("brief")  # copy.deepcopy(conf.BRIEF_LOGGER)
        # self.detailed_logger = logging.getLogger("detailed")  # copy.deepcopy(conf.DETAILED_LOGGER)

        print_config(self.brief_logger, self.detailed_logger, conf.MODEL,
                     self.source_object.rsplit("/", 1)[1], self.source_function,
                     self.target_variants[0]['filename'].rsplit("/", 1)[1], self.target_variants[0]['name'])

        if conf.MODEL == "SAFE":
            self.model.initialize_model("SAFE", self.r2_source, self.target_variants, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)

        elif conf.MODEL == "GEMINI":
            self.model.initialize_model("GEMINI", self.r2_source, self.target_variants, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "GMN":
            self.model.initialize_model("GMN", self.r2_source, self.target_variants, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
        elif conf.MODEL == "ASM2VEC":
            self.model.initialize_model("ASM2VEC", self.r2_source, self.target_variants, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "JTRANS":
            self.model.initialize_model("JTRANS", self.r2_source, self.target_variants, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "BINBERT":
            self.model.initialize_model("BINBERT", self.r2_source, self.target_variants, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "PALMTREE":
            self.model.initialize_model("PALMTREE", self.r2_source, self.target_variants, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "BINFINDER":
            self.model.initialize_model("BINFINDER", self.r2_source, self.target_variants, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "TREX":
            self.model.initialize_model("TREX", self.r2_source, self.target_variants, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)
        elif conf.MODEL == "ZEEK":
            self.model.initialize_model("ZEEK", self.r2_source, self.target_variants, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
            conf.setup_target_embd(self.source_function, self.target_function)
            self.model.set_target_embd(conf.TARGET_EMBD)

        init_similarities_pool = self.model.evaluate(is_first=True)

        if conf.OPTIMIZER == "greedy" or conf.OPTIMIZER == "random" or conf.OBFUSCATOR != None:
            self.init_similarity = min(init_similarities_pool) if conf.ATT_TYPE == 0 else max(init_similarities_pool)
            self.init_variant = init_similarities_pool.index(self.init_similarity)
        elif conf.OPTIMIZER == "greedy_mean":
            self.init_similarity = np.average(init_similarities_pool)

        if conf.IS_STAT:
            self.experiment_name = uuid.uuid4()
            experiment_path = f"{conf.FINAL_CFG_PATH}/{self.experiment_name}/"

            self.state_save = StateSave(experiment_path, stats_name=uuid.uuid4(), cfg_name=uuid.uuid4(),
                                        initial_similarity=self.init_similarity,
                                        num_initial_nodes=self.get_initial_number_of_nodes(),
                                        num_initial_instrs=self.get_initial_number_of_instructions())

            self.detailed_logger.info("[Main] Initial similarity: {}".format(self.init_similarity))
            self.brief_logger.info("[Main] Initial similarity: {}".format(self.init_similarity))

        return True

    def get_initial_similarity(self):
        return self.init_similarity

    def get_initial_number_of_nodes(self):
        return self.r2_source['cfg'].number_of_nodes()

    def get_initial_number_of_instructions(self):

        count = 0
        for n in self.r2_source['cfg'].nodes(data=True):
            count += len(n[1]['disasm'])

        return count

    def get_target_number_of_instructions(self):

        variants_num_instrs = []
        for var in self.target_variants:
            count = 0
            for n in var['cfg'].nodes(data=True):
                count += len(n[1]['disasm'])

            variants_num_instrs.append(count)

        return np.average(variants_num_instrs)

    def get_target_number_of_nodes(self):

        variants_num_nodes = []
        for var in self.target_variants:
            variants_num_nodes.append(var['cfg'].number_of_nodes())

        return np.average(variants_num_nodes)


class Initializer_2_models:

    def __init__(self, conf, model, model_2, source_object, source_function, target_obj, target_function):

        self.path = conf.DATA_PATH
        self.source_object = source_object
        self.source_function = source_function
        self.target_object = target_obj
        self.target_function = target_function

        self.r2_source = None
        self.r2_target = None

        self.model = model
        self.model_2 = model_2
        self.init_similarity = 0

        self.state_save = None
        self.experiment_name = None

        self.brief_logger = None
        self.detailed_logger = None

    @staticmethod
    def get_entry_points(cfg):
        entry_points = []
        for n in cfg.nodes(data=True):
            n_ep = n[1]['entry_point']
            entry_points.append(n_ep)

        return entry_points

    def initialize(self, conf):

        # Get CFG for source and target
        # self.r2_source = get_cfg(self.path + self.source_object, self.source_function)
        r2_source_extractor = Extractor(self.path + self.source_object, self.source_function, libc)
        self.r2_source = r2_source_extractor.extract_func_cfg()

        # self.r2_target = get_cfg(self.path + self.target_object, self.target_function)
        r2_target_extractor = Extractor(self.path + self.target_object, self.target_function, libc)
        self.r2_target = r2_target_extractor.extract_func_cfg()

        if conf.IS_STAT:
            self.brief_logger = conf.BRIEF_LOGGER
            self.detailed_logger = conf.DETAILED_LOGGER

            print_config(self.brief_logger, self.detailed_logger, conf.MODEL,
                         self.source_object.rsplit("/", 1)[1], self.source_function,
                         self.target_object.rsplit("/", 1)[1], self.target_function)

        self.model.initialize_model(conf.MODEL, self.r2_source, self.r2_target, conf.IS_STAT,
                                    self.brief_logger, self.detailed_logger)

        self.model_2.initialize_model(conf.MODEL_2, self.r2_source, self.r2_target, conf.IS_STAT,
                                      self.brief_logger, self.detailed_logger)

        conf.setup_target_embd(self.source_function, self.target_function)
        self.model.set_target_embd(conf.TARGET_EMBD_1)
        self.model_2.set_target_embd(conf.TARGET_EMBD_2)

        self.init_similarity_1 = self.model.evaluate()
        self.init_similarity_2 = self.model_2.evaluate()
        self.init_similarity = np.average([self.init_similarity_1, self.init_similarity_2])

        self.experiment_name = uuid.uuid4()
        experiment_path = f"{conf.FINAL_CFG_PATH}/{self.experiment_name}/"

        self.state_save = StateSave_2_models(experiment_path, stats_name=uuid.uuid4(), cfg_name=uuid.uuid4(),
                                             initial_similarity_1=self.init_similarity_1,
                                             initial_similarity_2=self.init_similarity_2,
                                             num_initial_nodes=self.get_initial_number_of_nodes(),
                                             num_initial_instrs=self.get_initial_number_of_instructions())

        if conf.IS_STAT:
            self.detailed_logger.info("[Main] Initial similarity: {}".format(self.init_similarity))
            self.brief_logger.info("[Main] Initial similarity: {}".format(self.init_similarity))

        return True

    def get_initial_similarity(self):
        return self.init_similarity

    def get_initial_similarity_1(self):
        return self.init_similarity_1

    def get_initial_similarity_2(self):
        return self.init_similarity_2

    def get_initial_number_of_nodes(self):
        return self.r2_source['cfg'].number_of_nodes()

    def get_target_numer_of_nodes(self):
        return self.r2_target['cfg'].number_of_nodes()

    def get_initial_number_of_instructions(self):

        count = 0
        for n in self.r2_source['cfg'].nodes(data=True):
            count += len(n[1]['disasm'])

        return count

    def get_target_number_of_instructions(self):

        count = 0
        for n in self.r2_target['cfg'].nodes(data=True):
            count += len(n[1]['disasm'])

        return count

    # use when combining multiple attacks
    def set_r2_source(self, source_cfg):
        self.r2_source['cfg'] = source_cfg

    # use when combining multiple attacks
    def set_initial_similarity(self, sim):
        self.init_similarity = sim


CFG_PATH = "/app/vol/CFGExtractor/extracted_cfgs_variants"


class InitializerForPool:

    def __init__(self, conf, model, pool_embeddings, target_object, target_function, target_cfg=None,
                 function_pool=None):

        self.path = conf.DATA_PATH

        self.target_object = target_object
        self.target_function = target_function
        self.target_cfg = target_cfg

        self.pool_embeddings = pool_embeddings
        self.pool_functions = function_pool

        self.r2_target = None

        self.model = model

        self.brief_logger = None
        self.detailed_logger = None

    def initialize_for_pool(self, conf):

        self.brief_logger = conf.BRIEF_LOGGER
        self.detailed_logger = conf.DETAILED_LOGGER

        use_angr = True if conf.MODEL == "PALMTREE" else False

        # self.r2_target = get_cfg(self.path + self.target_object, self.target_function)
        r2_target_extractor = Extractor(self.path + self.target_object, self.target_function, libc, use_angr=use_angr)
        self.r2_target = r2_target_extractor.extract_func_cfg(use_angr=use_angr)

        if self.target_cfg is not None:
            self.r2_target['cfg'] = self.target_cfg

        if conf.MODEL == "SAFE":
            self.model.initialize_model("SAFE", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
        elif conf.MODEL == "JTRANS":
            self.model.initialize_model("JTRANS", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
        elif conf.MODEL == "GEMINI":
            self.model.initialize_model("GEMINI", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
        elif conf.MODEL == "GMN":
            self.model.initialize_model("GMN", self.r2_target, self.pool_embeddings, self.pool_functions, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
        elif conf.MODEL == "PALMTREE":
            self.model.initialize_model("PALMTREE", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
        elif conf.MODEL == "BINFINDER":
            self.model.initialize_model("BINFINDER", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
        elif conf.MODEL == "TREX":
            self.model.initialize_model("TREX", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)
        elif conf.MODEL == "ZEEK":
            self.model.initialize_model("ZEEK", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                        self.brief_logger, self.detailed_logger)

        return True


CFG_PATH = "/app/vol/CFGExtractor/extracted_cfgs_variants"


class InitializerForTransferability:

    def __init__(self, conf, model, pool_embeddings, target_object, target_function, target_cfg=None,
                 function_pool=None):

        self.path = conf.DATA_PATH

        self.target_object = target_object
        self.target_function = target_function
        self.target_cfg = target_cfg

        self.pool_embeddings = pool_embeddings
        self.pool_functions = function_pool

        self.r2_target = None

        self.target_model = model

        self.brief_logger = None
        self.detailed_logger = None

    def initialize_for_transferability(self, conf):

        self.brief_logger = conf.BRIEF_LOGGER
        self.detailed_logger = conf.DETAILED_LOGGER

        use_angr = True if conf.TARGET_MODEL == "PALMTREE" else False

        # self.r2_target = get_cfg(self.path + self.target_object, self.target_function)
        r2_target_extractor = Extractor(self.path + self.target_object, self.target_function, libc, use_angr=use_angr)
        self.r2_target = r2_target_extractor.extract_func_cfg(use_angr=use_angr)

        if self.target_cfg is not None:
            self.r2_target['cfg'] = self.target_cfg

        if conf.TARGET_MODEL == "SAFE":
            self.target_model.initialize_model("SAFE", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                               self.brief_logger, self.detailed_logger)
        elif conf.TARGET_MODEL == "JTRANS":
            self.target_model.initialize_model("JTRANS", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                               self.brief_logger, self.detailed_logger)
        elif conf.TARGET_MODEL == "GEMINI":
            self.target_model.initialize_model("GEMINI", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                               self.brief_logger, self.detailed_logger)
        elif conf.TARGET_MODEL == "GMN":
            self.target_model.initialize_model("GMN", self.r2_target, self.pool_embeddings, self.pool_functions,
                                               conf.IS_STAT,
                                               self.brief_logger, self.detailed_logger)
        elif conf.TARGET_MODEL == "PALMTREE":
            self.target_model.initialize_model("PALMTREE", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                               self.brief_logger, self.detailed_logger)
        elif conf.TARGET_MODEL == "BINFINDER":
            self.target_model.initialize_model("BINFINDER", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                               self.brief_logger, self.detailed_logger)
        elif conf.TARGET_MODEL == "TREX":
            self.target_model.initialize_model("TREX", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                               self.brief_logger, self.detailed_logger)
        elif conf.TARGET_MODEL == "ZEEK":
            self.target_model.initialize_model("ZEEK", self.r2_target, self.pool_embeddings, None, conf.IS_STAT,
                                               self.brief_logger, self.detailed_logger)

        return True
