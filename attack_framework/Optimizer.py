from abc import ABC, abstractmethod

from utils.utils import get_number_of_instructions


# Abstract class for optimizers
class Optimizer(ABC):

    def __init__(self, initializer, config):

        self.path = initializer.path

        self.original_size = initializer.get_initial_number_of_instructions()

        self.model = initializer.model
        self.initial_similarity = initializer.init_similarity

        self.att_type = config.ATT_TYPE
        self.th = 1.0 if self.att_type == 0 else 0.0

        self.iterations = config.ITERATIONS

        self.brief_logger = initializer.brief_logger
        self.detailed_logger = initializer.detailed_logger

        self.is_stat = config.IS_STAT
        self.stat_file = config.STAT_NAME

        self.state_save = initializer.state_save

        self.l = config.LAMBDA  # scaling factor for modification size
        self.use_importance = config.IMPORTANCE

    @abstractmethod
    def execute_steps(self, pool=None):
        pass

    @abstractmethod
    def execute_single_step(self, state, strands, pool=None):
        pass

    def scale_sims(self, states, similarities):

        scaled_sims = []
        for idx, s in enumerate(states):
            scaling_factor = self.l * (abs(get_number_of_instructions(s)-self.original_size))
            scaled_sims.append(similarities[idx] - scaling_factor if self.att_type == 0 else
                               similarities[idx] + scaling_factor)

        return scaled_sims
