import logging
import os
import pandas as pd

import uuid

ROOT_PATH = "/app/vol/"

ATT_TYPE = {0: "TARGETED", 1: "UNTARGETED"}


class Config:

    def __init__(self):

        self.DATA_PATH = f"{ROOT_PATH}advDB/sources/"

        self.LOGGING_PATH = None
        self.IS_STAT = False

        self.MODEL = None

        self.ATT_TYPE = None
        self.SPLIT = None

        self.TARGET_EMBD = None

        self.STAT_PATH = None
        self.STAT_NAME = None

        self.BRIEF_LOGGER = None
        self.DETAILED_LOGGER = None

    @staticmethod
    def get_default_config_for_query(args):

        config = Config()

        config.SPLIT = args.split
        config.SUB_SPLIT = args.sub_split

        config.DATA_PATH = args.data_path

        # attack on query function
        config.POOL_PATH = args.pool_path

        config.MODEL = args.target_model

        config.ATT_TYPE = args.att_type
        config.OPTIMIZER = args.optimizer

        config.TRANSFORMATION = args.transformation

        config.ITERATIONS = args.iterations
        config.LAMBDA = args.lambda_factor
        config.NUM_POSITIONS = args.num_positions
        config.H_PERCENTAGE = args.heavy_percentage

        config.IMPORTANCE = True if args.use_importance else False

        importance_folder = "imp" if config.IMPORTANCE else "rand"
        config.IMPORTANCE_FOLDER = importance_folder

        config.IS_STAT = True if args.get_stats else False

        config.OBFUSCATOR = args.obfuscator

        if config.IS_STAT:
            logging_root = "logging_query"
            stats_root = "stats_query"

            config.BASE_LOGGING_PATH = os.path.join(ROOT_PATH, logging_root, config.OPTIMIZER,
                                                    config.TRANSFORMATION, ATT_TYPE[config.ATT_TYPE], config.MODEL)
            config.LOGGING_PATH = os.path.join(config.BASE_LOGGING_PATH, str(config.NUM_POSITIONS),
                                               str(config.H_PERCENTAGE),
                                               importance_folder, str(config.LAMBDA),
                                               f"{config.ITERATIONS}_ITERS", f"SPLIT_{config.SPLIT}",
                                               f"{config.SPLIT}_{config.SUB_SPLIT}")
            os.makedirs(config.LOGGING_PATH, exist_ok=True)

            config.BASE_STAT_PATH = os.path.join(ROOT_PATH, stats_root, config.OPTIMIZER, config.TRANSFORMATION,
                                                 ATT_TYPE[config.ATT_TYPE], config.MODEL)
            config.FINAL_STAT_PATH = os.path.join(config.BASE_STAT_PATH, str(config.NUM_POSITIONS),
                                                  str(config.H_PERCENTAGE),
                                                  importance_folder, str(config.LAMBDA),
                                                  f"{config.ITERATIONS}_ITERS", f"SPLIT_{config.SPLIT}")
            os.makedirs(config.FINAL_STAT_PATH, exist_ok=True)

            config.FINAL_CFG_PATH = os.path.join(config.FINAL_STAT_PATH, f"{config.SPLIT}_{config.SUB_SPLIT}")
            os.makedirs(config.FINAL_CFG_PATH, exist_ok=True)

            # INITIALIZE FINAL STAT FILE
            config.FINAL_STAT_NAME = f"{config.FINAL_CFG_PATH}/stat_{config.MODEL}_{ATT_TYPE[config.ATT_TYPE]}_{config.SPLIT}_{config.SUB_SPLIT}.csv"  # set split instead of _test

            if not os.path.exists(config.FINAL_STAT_NAME):
                record = {
                    'source_object': '',
                    'source_function': '',
                    'source_c': '',
                    'source_func_line': '',
                    'source_gcc': '',
                    'target_object': '',
                    'target_function': '',
                    'initial_similarity': '',
                    'final_similarity': '',
                    'num_initial_nodes': '',
                    'num_final_nodes': '',
                    'num_initial_instructions': '',
                    'num_final_instructions': '',
                    'transformation_type': '',
                    'total_time': '',
                    'iterations_folder': ''
                }

                df = pd.DataFrame([record])

                df.to_csv(config.FINAL_STAT_NAME, index=False, mode='a')

            format = logging.Formatter('%(levelname)s: %(message)s')
            config.BRIEF_LOGGER = config.setup_logger("brief", f"{config.LOGGING_PATH}/brief_logger.log",
                                                      format=format)

            format = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
            config.DETAILED_LOGGER = config.setup_logger("detailed",
                                                         f"{config.LOGGING_PATH}/detailed_logger.log",
                                                         format=format)

        return config

    @staticmethod
    def config_for_reconstruction(args):

        config = Config()

        config.DATA_PATH = os.path.join(args.data_path, "sources")
        config.DATA_PATH_FOR_EXTRACT = os.path.join(args.data_path, "builds")
        config.SOURCES_PATH = os.path.join(args.data_path, "sources")
        config.BACKUP_PATH = os.path.join(args.data_path, "backup")
        config.SPLIT = args.split
        config.SUB_SPLIT = args.sub_split
        config.MODEL = args.target_model

        config.ATT_TYPE = args.att_type

        config.ITERATIONS = args.iterations

        config.LAMBDA = args.lambda_factor

        config.NUM_POSITIONS = args.num_positions
        config.H_PERCENTAGE = args.heavy_percentage

        config.IMPORTANCE = True if args.use_importance else False

        importance_folder = "imp" if config.IMPORTANCE else "rand"
        config.IMPORTANCE_FOLDER = importance_folder

        config.IS_STAT = args.get_stats  # True if args.get_stats is not None else False

        config.OPTIMIZER = args.optimizer
        config.TRANSFORMATION = args.transformation if args.transformation else "combo"

        config.SEARCH_DEPTH = args.search_depth

        config.BASE_LOGGING_PATH = os.path.join(ROOT_PATH, "logging_rec", config.OPTIMIZER,
                                                config.TRANSFORMATION, ATT_TYPE[config.ATT_TYPE], config.MODEL)
        config.LOGGING_PATH = os.path.join(config.BASE_LOGGING_PATH, str(config.NUM_POSITIONS),
                                           str(config.H_PERCENTAGE),
                                           importance_folder, str(config.LAMBDA),
                                           f"{config.ITERATIONS}_ITERS", f"SPLIT_{config.SPLIT}",
                                           f"{config.SPLIT}_{config.SUB_SPLIT}")
        os.makedirs(config.LOGGING_PATH, exist_ok=True)

        config.SIM_BASE_STAT_PATH = os.path.join(ROOT_PATH, "stats", config.OPTIMIZER, config.TRANSFORMATION,
                                                 ATT_TYPE[config.ATT_TYPE], config.MODEL)
        config.SIM_STAT_PATH = os.path.join(config.SIM_BASE_STAT_PATH, str(config.NUM_POSITIONS),
                                            str(config.H_PERCENTAGE),
                                            importance_folder, str(config.LAMBDA),
                                            f"{config.ITERATIONS}_ITERS")

        config.REC_BASE_STAT_PATH = os.path.join(ROOT_PATH, "stats_rec", config.OPTIMIZER, config.TRANSFORMATION,
                                                 ATT_TYPE[config.ATT_TYPE], config.MODEL)
        config.REC_STAT_PATH = os.path.join(config.REC_BASE_STAT_PATH, str(config.NUM_POSITIONS),
                                            str(config.H_PERCENTAGE),
                                            importance_folder, str(config.LAMBDA), f"{config.ITERATIONS}_ITERS",
                                            f"SPLIT_{config.SPLIT}", f"{config.SPLIT}_{config.SUB_SPLIT}")

        os.makedirs(config.REC_STAT_PATH, exist_ok=True)

        config.REC_STAT_FILE = f"{config.REC_STAT_PATH}/stats_{config.MODEL}_{ATT_TYPE[config.ATT_TYPE]}_{config.SPLIT}_{config.SUB_SPLIT}.csv"

        return config

    def setup_target_embd(self, source_func, target_func):

        if hasattr(self, 'MODEL_2') and self.MODEL_2 is not None:
            self.TARGET_EMBD_1 = f"{ROOT_PATH}{self.MODEL}_{self.IMPORTANCE_FOLDER}_{ATT_TYPE[self.ATT_TYPE]}_{self.SPLIT}_{self.SUB_SPLIT}_{source_func}_{target_func}_{uuid.uuid4()}.json"
            self.TARGET_EMBD_2 = f"{ROOT_PATH}{self.MODEL_2}_{self.IMPORTANCE_FOLDER}_{ATT_TYPE[self.ATT_TYPE]}_{self.SPLIT}_{self.SUB_SPLIT}_{source_func}_{target_func}_{uuid.uuid4()}.json"
        else:

            self.TARGET_EMBD = f"{ROOT_PATH}{self.MODEL}_{self.IMPORTANCE_FOLDER}_{ATT_TYPE[self.ATT_TYPE]}_{self.SPLIT}_{self.SUB_SPLIT}_{source_func}_{target_func}_{uuid.uuid4()}"

    @staticmethod
    def setup_logger(name, log_file, format, level=logging.DEBUG):
        handler = logging.FileHandler(log_file)
        handler.setFormatter(format)
        logger = logging.getLogger(name)
        logger.propagate = False
        logger.setLevel(level)
        logger.addHandler(handler)
        return logger


class ConfigForPool:

    def __init__(self):

        self.LOGGING_PATH = None
        self.IS_STAT = False

        self.MODEL = None

        self.ATT_TYPE = None
        self.SPLIT = None

        self.TARGET_EMBD = None

        self.STAT_PATH = None
        self.STAT_NAME = None

        self.BRIEF_LOGGER = None
        self.DETAILED_LOGGER = None

    @staticmethod
    def get_config_for_pool(args):

        config = ConfigForPool()

        config.SPLIT = args.split
        config.SUB_SPLIT = args.sub_split

        config.DATA_PATH = args.data_path
        config.POOL_PATH = args.pool_path

        config.POOL_SIZE = args.pool_size

        config.MODEL = args.target_model

        config.ATT_TYPE = args.att_type
        config.OPTIMIZER = args.optimizer

        config.TRANSFORMATION = args.transformation

        config.ITERATIONS = args.iterations
        config.LAMBDA = args.lambda_factor
        config.NUM_POSITIONS = args.num_positions
        config.H_PERCENTAGE = args.heavy_percentage

        importance_folder = "imp" if args.use_importance else "rand"
        config.IMPORTANCE_FOLDER = importance_folder

        config.SEARCH_DEPTH = args.search_depth

        config.BASE_LOGGING_PATH = os.path.join(ROOT_PATH, "logging_fs_query", config.OPTIMIZER, config.TRANSFORMATION,
                                                ATT_TYPE[config.ATT_TYPE], config.MODEL)
        config.LOGGING_PATH = os.path.join(config.BASE_LOGGING_PATH, str(config.NUM_POSITIONS),
                                           str(config.H_PERCENTAGE),
                                           importance_folder, str(config.LAMBDA), f"{config.ITERATIONS}_ITERS",
                                           f"{config.POOL_SIZE}_POOL", f"SPLIT_{config.SPLIT}",
                                           f"{config.SPLIT}_{config.SUB_SPLIT}")
        os.makedirs(config.LOGGING_PATH, exist_ok=True)

        # PATH TO FINAL STAT FILE
        if config.OPTIMIZER == "greedy":
            config.BASE_STAT_PATH = os.path.join(ROOT_PATH, "stats_query", config.OPTIMIZER, config.TRANSFORMATION,
                                                 ATT_TYPE[config.ATT_TYPE], config.MODEL)
        else:
            config.BASE_STAT_PATH = os.path.join(ROOT_PATH, "stats_query", config.OPTIMIZER, config.TRANSFORMATION,
                                                 ATT_TYPE[config.ATT_TYPE], "random_1")
        config.FINAL_STAT_PATH = os.path.join(config.BASE_STAT_PATH, str(config.NUM_POSITIONS),
                                              str(config.H_PERCENTAGE),
                                              importance_folder, str(config.LAMBDA),
                                              f"{config.ITERATIONS}_ITERS", f"SPLIT_{config.SPLIT}")
        os.makedirs(config.FINAL_STAT_PATH, exist_ok=True)

        config.FINAL_CFG_PATH = os.path.join(config.FINAL_STAT_PATH, f"{config.SPLIT}_{config.SUB_SPLIT}")
        os.makedirs(config.FINAL_CFG_PATH, exist_ok=True)

        if config.OPTIMIZER == "greedy":
            config.FINAL_STAT_NAME = os.path.join(config.FINAL_CFG_PATH,
                                                  f"stat_{config.MODEL}_{ATT_TYPE[config.ATT_TYPE]}_{config.SPLIT}_{config.SUB_SPLIT}.csv")
        else:
            config.FINAL_STAT_NAME = os.path.join(config.FINAL_CFG_PATH,
                                                  f"stat_SAFE_{ATT_TYPE[config.ATT_TYPE]}_{config.SPLIT}_{config.SUB_SPLIT}.csv")

        # PATH TO FUNCTION SEARCH STAT FILE
        config.BASE_FS_STAT_PATH = os.path.join(ROOT_PATH, "stats_fs_query", config.OPTIMIZER, config.TRANSFORMATION,
                                                ATT_TYPE[config.ATT_TYPE], config.MODEL, str(config.NUM_POSITIONS),
                                                str(config.H_PERCENTAGE),
                                                importance_folder, str(config.LAMBDA), f"{config.ITERATIONS}_ITERS",
                                                f"{config.POOL_SIZE}_POOL")
        config.FINAL_FS_STAT_PATH = os.path.join(config.BASE_FS_STAT_PATH, f"SPLIT_{config.SPLIT}")
        os.makedirs(config.FINAL_FS_STAT_PATH, exist_ok=True)

        config.FINAL_FS_PATH = os.path.join(config.FINAL_FS_STAT_PATH, f"{config.SPLIT}_{config.SUB_SPLIT}")
        os.makedirs(config.FINAL_FS_PATH, exist_ok=True)

        config.FINAL_FS_STAT_NAME = os.path.join(config.FINAL_FS_PATH,
                                                 f"stat_{config.MODEL}_{ATT_TYPE[config.ATT_TYPE]}_{config.SPLIT}_{config.SUB_SPLIT}")

        format = logging.Formatter('%(levelname)s: %(message)s')
        config.BRIEF_LOGGER = config.setup_logger("brief", os.path.join(config.LOGGING_PATH, "brief_logger.log"),
                                                  format=format)

        format = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        config.DETAILED_LOGGER = config.setup_logger("detailed",
                                                     os.path.join(config.LOGGING_PATH, "detailed_logger.log"),
                                                     format=format)

        return config

    @staticmethod
    def setup_logger(name, log_file, format, level=logging.DEBUG):
        handler = logging.FileHandler(log_file)
        handler.setFormatter(format)
        logger = logging.getLogger(name)
        logger.propagate = False
        logger.setLevel(level)
        logger.addHandler(handler)
        return logger


class ConfigForTransfer:

    def __init__(self):
        self.LOGGING_PATH = None
        self.IS_STAT = False

        self.SOURCE_MODEL = None
        self.TARGET_MODEL = None

        self.ATT_TYPE = None
        self.SPLIT = None

        self.TARGET_EMBD = None

        self.STAT_PATH = None
        self.STAT_NAME = None

        self.BRIEF_LOGGER = None
        self.DETAILED_LOGGER = None

    @staticmethod
    def get_config_for_transfer(args):
        config = ConfigForTransfer()
        config.POOL_PATH = args.pool_path
        config.DATA_PATH = args.data_path

        config.SPLIT = args.split
        config.SUB_SPLIT = args.sub_split

        config.SOURCE_MODEL = args.source_model
        config.TARGET_MODEL = args.target_model

        config.ATT_TYPE = args.att_type
        config.OPTIMIZER = args.optimizer

        config.TRANSFORMATION = args.transformation

        config.ITERATIONS = args.iterations
        config.LAMBDA = args.lambda_factor
        config.NUM_POSITIONS = args.num_positions
        config.H_PERCENTAGE = args.heavy_percentage

        config.POOL_SIZE = args.pool_size

        importance_folder = "imp" if args.use_importance else "rand"
        config.IMPORTANCE_FOLDER = importance_folder

        config.SEARCH_DEPTH = args.search_depth

        # PATH TO ADV EXAMPLE AGAINST SOURCE MODEL
        config.SOURCE_MODEL_BASE_PATH = os.path.join(ROOT_PATH, "stats_query", config.OPTIMIZER, config.TRANSFORMATION,
                                                     ATT_TYPE[config.ATT_TYPE], config.SOURCE_MODEL)
        config.SOURCE_MODEL_STATS_PATH = os.path.join(config.SOURCE_MODEL_BASE_PATH, str(config.NUM_POSITIONS),
                                                      str(config.H_PERCENTAGE),
                                                      importance_folder, str(config.LAMBDA),
                                                      f"{config.ITERATIONS}_ITERS")

        # PATH TO FUNCTION SEARCH RESULTS FOR TARGET MODEL (to load first successful result)
        config.SOURCE_MODEL_FS_BASE_PATH = os.path.join(ROOT_PATH, "stats_fs_query", config.OPTIMIZER,
                                                        config.TRANSFORMATION,
                                                        ATT_TYPE[config.ATT_TYPE], config.SOURCE_MODEL)
        config.SOURCE_MODEL_FS_PATH = os.path.join(config.SOURCE_MODEL_FS_BASE_PATH, str(config.NUM_POSITIONS),
                                                   str(config.H_PERCENTAGE),
                                                   importance_folder, str(config.LAMBDA), f"{config.ITERATIONS}_ITERS")

        config.SOURCE_FINAL_CFG_PATH = os.path.join(config.SOURCE_MODEL_STATS_PATH, f"SPLIT_{config.SPLIT}",
                                                    f"{config.SPLIT}_{config.SUB_SPLIT}")
        config.SOURCE_FINAL_STATS_PATH = os.path.join(config.SOURCE_FINAL_CFG_PATH,
                                                      f"stat_{config.SOURCE_MODEL}_{ATT_TYPE[config.ATT_TYPE]}_{config.SPLIT}_{config.SUB_SPLIT}.csv")

        # PATH TO FUNCTION SEARCH RESULTS FOR TARGET MODEL (to load K-th thresholds)
        config.TARGET_MODEL_FS_BASE_PATH = os.path.join(ROOT_PATH, "stats_fs_query", config.OPTIMIZER,
                                                        config.TRANSFORMATION,
                                                        ATT_TYPE[config.ATT_TYPE], config.TARGET_MODEL)
        config.TARGET_MODEL_FS_PATH = os.path.join(config.TARGET_MODEL_FS_BASE_PATH, str(config.NUM_POSITIONS),
                                                   str(config.H_PERCENTAGE),
                                                   importance_folder, str(config.LAMBDA), f"{config.ITERATIONS}_ITERS")

        # PATH TO TRANSFERABILITY STAT FILE
        config.BASE_TRANSF_STAT_PATH = os.path.join(ROOT_PATH, "stats_query_transf", config.OPTIMIZER,
                                                    config.TRANSFORMATION,
                                                    ATT_TYPE[config.ATT_TYPE], config.SOURCE_MODEL, config.TARGET_MODEL)
        config.BASE_TRANSF_STAT_PATH = os.path.join(config.BASE_TRANSF_STAT_PATH, str(config.NUM_POSITIONS),
                                                    str(config.H_PERCENTAGE),
                                                    importance_folder, str(config.LAMBDA), f"{config.ITERATIONS}_ITERS",
                                                    f"{config.POOL_SIZE}_POOL")
        os.makedirs(config.BASE_TRANSF_STAT_PATH, exist_ok=True)

        config.FINAL_TRANSF_PATH = os.path.join(config.BASE_TRANSF_STAT_PATH, f"SPLIT_{config.SPLIT}",
                                                f"{config.SPLIT}_{config.SUB_SPLIT}")
        os.makedirs(config.FINAL_TRANSF_PATH, exist_ok=True)

        config.FINAL_TRANSF_STAT_NAME = os.path.join(config.FINAL_TRANSF_PATH,
                                                     f"stat_{config.SOURCE_MODEL}_{config.TARGET_MODEL}_{ATT_TYPE[config.ATT_TYPE]}_{config.SPLIT}_{config.SUB_SPLIT}")

        print(config.FINAL_TRANSF_STAT_NAME)

        return config

    @staticmethod
    def setup_logger(name, log_file, format, level=logging.DEBUG):
        handler = logging.FileHandler(log_file)
        handler.setFormatter(format)
        logger = logging.getLogger(name)
        logger.propagate = False
        logger.setLevel(level)
        logger.addHandler(handler)
        return logger
