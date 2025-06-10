from abc import ABC, abstractmethod


class ModelForQueryAttack(ABC):

    def __init__(self):
        self.name = None

        self.r2_source = None
        self.r2_target_variants = None

        self.target_embd = None

        self.is_stat = None
        self.brief_logger = None
        self.detailed_logger = None

    def initialize_model(self, name, r2_source, target_variants, is_stat, brief_log, detailed_log):

        self.name = name

        self.r2_source = r2_source
        self.r2_target_variants = target_variants

        self.is_stat = is_stat
        self.brief_logger = brief_log
        self.detailed_logger = detailed_log

    @abstractmethod
    def evaluate(self, is_first=True):
        pass

    @abstractmethod
    def evaluate_batch(self, cfg_sources, multiproc_pool, variant_idx):
        pass

    def update_r2_source_cfg(self, r2_source_cfg):
        self.r2_source['cfg'] = r2_source_cfg

    def set_r2_source(self, r2_source_cfg, r2_source_strings):
        self.r2_source['cfg'] = r2_source_cfg
        self.r2_source['string_addresses'] = r2_source_strings

    def set_r2_target(self, r2_target_cfg, r2_target_strings):
        self.r2_target['cfg'] = r2_target_cfg
        self.r2_target['string_addresses'] = r2_target_strings

    def set_target_embd(self, target_embd):
        self.target_embd = target_embd


class ModelForPool(ABC):

    def __init__(self):
        self.name = None

        self.r2_target = None
        self.pool_embeddings = None

        self.r2_pool = None

        self.is_stat = None
        self.brief_logger = None
        self.detailed_logger = None

    def initialize_model(self, name, r2_target, pool_embeddings, r2_pool=None, is_stat=False, brief_log=None, detailed_log=None):
        self.name = name

        self.r2_target = r2_target
        self.pool_embeddings = pool_embeddings

        self.r2_pool = r2_pool

        self.is_stat = is_stat
        self.brief_logger = brief_log
        self.detailed_logger = detailed_log

    @abstractmethod
    def calculate_pool_embeddings(self, function_pool, pool):
        pass

    @abstractmethod
    def evaluate_batch(self, pool=None):
        pass


class ModelForTransfer(ABC):

    def __init__(self):

        self.r2_source = None
        self.r2_target = None

    def set_functions(self, r2_source, r2_target):

        self.r2_source = r2_source
        self.r2_target = r2_target

    @abstractmethod
    def calculate_similarity(self):
        pass