import random
import time

import gc

from Optimizer import Optimizer
from State import State

from utils.utils import get_number_of_instructions


class GreedyQuery(Optimizer):

    def __init__(self, initializer, config, space, eps=0.1, spat_strands=True,
                 keep_father=True, to_test=100, perc_max=0.50, num_snops=50):

        super().__init__(initializer, config)

        random.seed(10)

        self.space = space

        self.max_to_test = to_test

        self.epsilon = 1 - eps
        self.state = State()
        self.state.init_attributes(initializer, config, initializer.get_initial_similarity())

        self.max_iters = config.ITERATIONS

        self.spat_strands = spat_strands
        if self.spat_strands:
            self.keep_father = keep_father

            self.children_for_each_elected_embedding = 5

            # Percentage of neighbours
            self.percentage_max = 1 - perc_max
            # Percentage of random instructions
            self.percentage_random = 1 - self.percentage_max

            # Num of single/pair semantics-nops
            self.num_snops = num_snops

        self.targeted = True if self.att_type == 0 else False

        # index for partial ordering
        self.variant_idx = initializer.init_variant

    def refresh_strands(self, strands, max_neighbour_for_strand=10, random_strands=80):
        refreshed = []

        for x in strands:
            n_strands = self.space.get_neighbors(x, num_neighbours=max_neighbour_for_strand)
            refreshed += [st for st in n_strands]

        refreshed += self.space.get_spreaded_strands(random_strands)

        refreshed += random.sample(self.space.semnops_strands, self.num_snops)

        return refreshed

    def execute_steps(self, pool=None):

        iter = 0
        best_iter, best_sim, best_cfg = 0, self.state.current_similarity, self.state.source_cfg

        strands = self.refresh_strands([], random_strands=self.max_to_test)

        applied_actions = []
        while iter < self.max_iters and not self.state.is_terminal_from_sim(best_sim):

            self.state, similarity, applied_act, strands = self.execute_single_step(self.state, strands, pool)

            self.detailed_logger.info(f"[GreedyOptimizer] New similarity: {self.state.current_similarity}, "
                                      f"Iter: {iter}")

            if (self.att_type == 0 and similarity > best_sim) or (self.att_type == 1 and similarity < best_sim):
                applied_actions.append(applied_act)
                best_sim = similarity
                best_cfg = self.state.source_cfg
                best_iter = iter

            # SAVE CURRENT STATE
            self.state_save.save_cfg(best_cfg, iter, best_iter, best_sim,
                                     best_cfg.number_of_nodes(), get_number_of_instructions(best_cfg),
                                     applied_act)

            iter += 1

        return best_sim, best_cfg, applied_actions

    def execute_single_step(self, current_state, strands, pool=None):
        possible_actions = current_state.get_actions_from_state(self.model, pool=pool, strands=strands,
                                                                use_importance=self.use_importance,
                                                                variant_idx=self.variant_idx)

        if self.is_stat:
            start = time.perf_counter()
        new_states = current_state.apply_multiple_actions(possible_actions, pool)
        if self.is_stat:
            end = time.perf_counter()
            self.detailed_logger.info(f"[GreedyOptimizer] Expand current state: {end - start}")

        if self.is_stat:
            start = time.perf_counter()
        cfgs_for_batch = [state.source_cfg for state in new_states]
        similarities = self.model.evaluate_batch(cfgs_for_batch, pool, self.variant_idx)

        scaled_sims = self.scale_sims(cfgs_for_batch, similarities)

        if self.is_stat:
            end = time.perf_counter()
            self.detailed_logger.info(f"[GreedyOptimizer] Run model in batch: {end - start}")

        for idx, sim in enumerate(similarities):
            new_states[idx].current_similarity = sim

        # eps-greedy strategy
        rand_extract = random.uniform(0, 1)
        if rand_extract < self.epsilon:
            self.detailed_logger.info(f"[GreedyOptimizer] Select local optimum")

            # Add factor for modification size
            idx_scaled_sim = scaled_sims.index(max(scaled_sims) if self.att_type == 0 else min(scaled_sims))
            new_similarity = float(similarities[idx_scaled_sim])
        else:
            self.detailed_logger.info(f"[GreedyOptimizer] Select suboptimum")
            new_similarity = float(random.choice(similarities))

        last_idx = int(similarities.index(new_similarity))

        new_state = new_states[last_idx]

        # update query function according to partial ordering
        start_part = time.perf_counter()
        self.model.update_r2_source_cfg(new_state.source_cfg)
        part_ordering_sims = self.model.evaluate(is_first=False)

        self.variant_idx = part_ordering_sims.index(
            min(part_ordering_sims)) if self.att_type == 0 else part_ordering_sims.index(max(part_ordering_sims))
        end_part = time.perf_counter()
        self.detailed_logger.info(f"[GreedyOptimizer] Update partial ordering: {end_part - start_part}")

        # update strands candidates' set
        new_strands = None

        if self.spat_strands:
            start = time.perf_counter()
            elected_number = int((self.percentage_max * self.max_to_test) / self.children_for_each_elected_embedding)
            random_number = self.max_to_test - elected_number * self.children_for_each_elected_embedding

            if rand_extract < self.epsilon:
                strandadd_indices = []
                for idx, act in enumerate(possible_actions):
                    if act.type == "strandadd":
                        strandadd_indices.append(idx)

                # update strands list with spatial-like strategy
                elected_indices = sorted(strandadd_indices, key=lambda i: scaled_sims[i], reverse=self.targeted)[
                                  :elected_number]

                elected = [{'ot_strand': possible_actions[i].strand, 'shellcode': possible_actions[i].shellcode,
                            'strand_id': possible_actions[i].strand_id} for i in elected_indices]

                new_strands = self.refresh_strands(elected,
                                                   max_neighbour_for_strand=self.children_for_each_elected_embedding,
                                                   random_strands=random_number)

            else:
                new_strands = self.refresh_strands([], random_strands=self.max_to_test)

            end = time.perf_counter()
            self.detailed_logger.info(f"[GreedyOptimizer] Update strands candidates: {end - start}")

        return new_state, new_similarity, possible_actions[last_idx].type, new_strands

