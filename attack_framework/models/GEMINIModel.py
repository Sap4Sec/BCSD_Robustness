from models.Model import ModelForPool, ModelForTransfer, ModelForQueryAttack

from models.GEMINI.gemini import calculate_similarity, calculate_similarity_batch, calculate_embeddings, \
    calculate_similarity_pool


class GEMINIModelForQueryAttack(ModelForQueryAttack):

    def __init__(self):
        super().__init__()

    def initialize_model(self, name, r2_source, target_variants, is_stat, brief_log, detailed_log):
        return super().initialize_model(name, r2_source, target_variants, is_stat, brief_log, detailed_log)

    def evaluate(self, is_first=True):
        if is_first:
            pool_embeddings = calculate_embeddings([t['cfg'] for t in self.r2_target_variants],
                                                   [t['string_addresses'] for t in self.r2_target_variants],
                                                   json_file=self.target_embd)
            return calculate_similarity_pool(pool_embeddings, self.r2_source['cfg'], self.r2_source['string_addresses'])
        return calculate_similarity_pool(None, self.r2_source['cfg'], self.r2_source['string_addresses'],
                                         self.target_embd, len(self.r2_target_variants))

    def evaluate_batch(self, cfg_sources, multiproc_pool, variant_idx):
        target_embd = f"{self.target_embd}_{variant_idx}.json"

        return calculate_similarity_batch(cfg_sources, self.r2_source['string_addresses'], target_embd,
                                          pool=multiproc_pool, is_stat=self.is_stat,
                                          detailed_logger=self.detailed_logger)


class GEMINIModelForPool(ModelForPool):

    def __init__(self):
        super().__init__()

    def initialize_model(self, name, r2_target, pool_embeddings, r2_pool, is_stat=False, brief_log=None,
                         detailed_log=None):
        super().initialize_model(name, r2_target, pool_embeddings, r2_pool, is_stat, brief_log, detailed_log)

    def calculate_pool_embeddings(self, function_pool, pool):
        return calculate_embeddings([t['cfg'] for t in function_pool], [t['string_addresses'] for t in function_pool],
                                    pool)

    def evaluate_batch(self, pool=None):
        return calculate_similarity_pool(self.pool_embeddings, self.r2_target['cfg'],
                                         self.r2_target['string_addresses'])


class GEMINIModelForTransfer(ModelForTransfer):

    def __init__(self):
        super().__init__()

    def calculate_similarity(self):
        source_cfg = self.r2_source['cfg']
        source_str = self.r2_source['string_addresses']
        target_cfg = self.r2_target['cfg']
        target_str = self.r2_target['string_addresses']

        return calculate_similarity(source_cfg, source_str, target_cfg, target_str,
                                    target_json=None, is_stat=False, detailed_logger=None)
