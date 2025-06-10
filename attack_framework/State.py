import uuid
from abc import ABC

from copy import deepcopy

import networkx as nx

import random
random.seed(10)

from Action import Action

from LLMProxy.InstructionImportance import get_positions

from CodeDisplacement import apply_disp_for_optimizer
from StrandInBlocks import apply_strandadd_for_optimizer
from SwapInBlocks import apply_swap_for_optimizer
from DeadBranchAddition import apply_dba_for_optimizer

import time


class State(ABC):

    def __init__(self):

        random.seed(10)

        self.path = None

        self.att_type = None
        self.th = None

        self.current_similarity = None

        self.source_cfg = None
        # self.source_strings = None
        self.source_addr_for_disp = None

        self.trans_types = ['strandadd', 'swap', 'displace', 'dba']
        self.top_k = None
        self.top_for_strands = None

        self.best_transformations = None

        self.last_disp_addr = 0  # for displacement

        self.max_iters = 0
        self.iter = 0

        self.is_stat = None
        self.detailed_logger = None
        self.brief_logger = None

    def init_attributes(self, initializer, config, similarity):

        self.path = initializer.path

        self.att_type = config.ATT_TYPE
        self.th = 1.0 if self.att_type == 0 else 0.0

        self.current_similarity = similarity

        self.source_cfg = initializer.r2_source['cfg']
        self.source_addr_for_disp = initializer.r2_source['addr_for_disp']

        self.trans_types = ['strandadd', 'swap', 'displace', 'dba']  # choose random for random attack
        self.top_k = config.NUM_POSITIONS  # set to 1 for random attack
        self.top_for_strands = (config.H_PERCENTAGE * self.top_k) // 100  # set to 1 for random attack

        self.last_disp_addr = 0  # for displacement

        self.max_iters = config.ITERATIONS
        self.iter = 0

        self.is_stat = config.IS_STAT
        self.detailed_logger = config.DETAILED_LOGGER
        self.brief_logger = config.BRIEF_LOGGER

    @staticmethod
    def copy_node(node_attrs):

        new_node = {
            'func_addr': node_attrs['func_addr'],
            'entry_point': node_attrs['entry_point'],
            'original_ep': node_attrs['original_ep'],
            'asm': node_attrs['asm'],
            'disasm': deepcopy(node_attrs['disasm']),
            'calls': node_attrs['calls'],
            'text_addr': node_attrs['text_addr'],
            'can_disp': node_attrs['can_disp'],
            'is_db': node_attrs['is_db'],
            'bb_disasm': node_attrs['bb_disasm'],
            'bb_heads': node_attrs['bb_heads'],
            'bb_mnems': node_attrs['bb_mnems']
            }

        return new_node

    def my_copy(self, node_ep):

        new_state = State()

        new_state.path = self.path

        new_state.source_cfg = nx.DiGraph()

        new_data = self.copy_node(self.source_cfg.nodes[node_ep])

        for node, data in self.source_cfg.nodes(data=True):
            if node == node_ep:
                new_state.source_cfg.add_node(node_ep, **new_data)
            else:
                new_state.source_cfg.add_node(node, **data)

        new_state.source_cfg.add_edges_from(self.source_cfg.edges(data=True))

        new_state.source_addr_for_disp = self.source_addr_for_disp

        # new_state.model = self.model
        new_state.att_type = self.att_type
        new_state.th = self.th

        new_state.current_similarity = self.current_similarity

        new_state.trans_types = self.trans_types
        new_state.top_k = self.top_k
        new_state.top_for_strands = self.top_for_strands

        new_state.last_disp_addr = self.last_disp_addr

        new_state.max_iters = self.max_iters
        new_state.iter = self.iter

        new_state.is_stat = self.is_stat
        new_state.detailed_logger = self.detailed_logger
        new_state.brief_logger = self.brief_logger

        return new_state

    def get_random_action(self, model, pool, strands=None, use_importance=True):

        top_for_strands = 1

        # top_k is 1 in this case
        random_positions = get_positions(model, self.source_cfg, self.current_similarity,
                                    self.top_k, pool, use_importance=use_importance,
                                    variant_idx=None, logger=self.detailed_logger)

        t_type = random.choice(self.trans_types)

        possible_actions = []
        if t_type == "strandadd":
            top_for_strands = top_for_strands if top_for_strands < len(random_positions) else len(random_positions)
            packed_strands = [[i, b] for i in random_positions for b in strands[:top_for_strands]]

            # best_instr X strands
            for pck_strand in packed_strands:
                action = self.get_action_type(t_type, pck_strand[0][0], pck_strand[0][1],
                                                strand=pck_strand[1])
                possible_actions.append(action)
        elif t_type == "dba":
            for instr in random_positions:
                random_strands = random.sample(strands, top_for_strands)
                for rs in random_strands:
                    action = self.get_action_type(t_type, instr[0], instr[1], strand=rs,
                                                source_addr_for_disp=self.source_addr_for_disp)
                    possible_actions.append(action)
        else:
            for instr in random_positions:
                action = self.get_action_type(t_type, instr[0], instr[1],
                                                source_addr_for_disp=self.source_addr_for_disp)
                possible_actions.append(action)

        return possible_actions

    def get_actions_from_state(self, model, pool, strands=None, use_importance=True, variant_idx=None):

        possible_actions = []

        if self.is_stat:
            start = time.perf_counter()

        best_instrs = get_positions(model, self.source_cfg, self.current_similarity,
                                    self.top_k, pool, use_importance=use_importance,
                                    variant_idx=variant_idx, logger=self.detailed_logger)
        if self.is_stat:
            end = time.perf_counter()
            self.detailed_logger.info(f"[State] Update important instructions: {end - start}")

            start = time.perf_counter()

        for t_type in self.trans_types:
            if t_type == "strandadd":
                self.top_for_strands = self.top_for_strands if self.top_for_strands < len(best_instrs) else len(best_instrs)
                packed_strands = [[i, b] for i in best_instrs for b in strands[:self.top_for_strands]]

                for pck_strand in packed_strands:
                    action = self.get_action_type(t_type, pck_strand[0][0], pck_strand[0][1],
                                                  strand=pck_strand[1])
                    possible_actions.append(action)
            elif t_type == "dba":
                for instr in best_instrs:
                    random_strands = random.sample(strands, self.top_for_strands)
                    for rs in random_strands:
                        action = self.get_action_type(t_type, instr[0], instr[1], strand=rs,
                                                    source_addr_for_disp=self.source_addr_for_disp)
                        possible_actions.append(action)
            else:
                for instr in best_instrs:
                    action = self.get_action_type(t_type, instr[0], instr[1],
                                                  source_addr_for_disp=self.source_addr_for_disp)
                    possible_actions.append(action)

        if self.is_stat:
            end = time.perf_counter()
            self.detailed_logger.info(f"[State] Create action objects: {end - start}")

        return possible_actions

    def get_action_type(self, t_type, block_addr, instr_addr, strand=None, source_addr_for_disp=None):

        if t_type == "strandadd":
            return Action("strandadd", block_addr, strand['ot_strand'], strand['shellcode'], strand['strand_id'],
                          strand['radare_st'], instr_addr, '')
        elif t_type == "swap":
            return Action("swap", block_addr, '', '', '', '', instr_addr, '')
        elif t_type == "displace":
            return Action("displace", block_addr, '', '', '', '', instr_addr, source_addr_for_disp)
        elif t_type == "dba":
            return Action("dba", block_addr, strand['ot_strand'], strand['shellcode'], strand['strand_id'],
                          strand['radare_st'], instr_addr, source_addr_for_disp)

        return None

    def get_new_state_from_action(self, action):

        new_state = self.my_copy(action.node)

        if action.type == "displace":
            new_state.source_cfg, new_state.source_addr_for_disp = apply_disp_for_optimizer(
                new_state.source_cfg, action.node, action.instr, action.source_addr_for_disp)
        elif action.type == "strandadd":
            new_state.source_cfg, to_increase = apply_strandadd_for_optimizer(new_state.source_cfg, action.node,
                                                                 action.strand, action.shellcode,
                                                                 action.radare_strand, action.instr)
            new_state.source_addr_for_disp += to_increase
        elif action.type == "swap":
            new_state.source_cfg = apply_swap_for_optimizer(new_state.source_cfg, action.node, action.instr)
        elif action.type == "dba":
            new_state.source_cfg, new_state.source_addr_for_disp = apply_dba_for_optimizer(
                new_state.source_cfg, action.node, action.instr,
                action.source_addr_for_disp, action.radare_strand)

        new_state.iter += 1

        return new_state

    def apply_action(self, action):

        newState = self.get_new_state_from_action(action)

        return newState

    # @profile
    def apply_multiple_actions(self, actions, pool):

        if self.is_stat:
            start = time.perf_counter()

        parameters = []
        for action in actions:
            parameters.append([self, action])

        new_states = pool.map(self.parallel_take_action, parameters,
                              chunksize=40)  # , chunksize=len(parameters)//N_PROCESSES)

        if self.is_stat:
            end = time.perf_counter()
            self.detailed_logger.info(f"[State] Apply multiple actions: {end - start}")

        return new_states

    def can_exit(self, model):

        # self.r2_source['cfg'] = self.source_cfg
        model.set_r2_source_cfg(self.source_cfg)

        new_similarity = model.evaluate()

        can_exit = self.is_terminal_from_sim(new_similarity)

        return can_exit

    def is_terminal_from_sim(self, sim):
        if (self.att_type == 0 and sim >= self.th) or (self.att_type == 1 and sim <= self.th) or \
                self.iter >= self.max_iters:
            print(f"TERMINAL - SIM:{sim}")
            return True

        return False

    def reward_from_state(self, model):
        model.set_r2_source_cfg(self.source_cfg)

        new_similarity = model.evaluate()
        if self.iter >= self.max_iters or (self.att_type == 0 and new_similarity >= self.th) or (
                self.att_type == 1 and new_similarity <= self.th):
            return new_similarity

        return 0

    def rewards_from_states(self, new_states, model):

        cfgs_for_batch = [state.source_cfg for state in new_states]
        similarities = model.evaluate_batch(cfgs_for_batch)

        rewards = [0] * len(similarities)
        for i, sim in enumerate(similarities):
            if self.iter >= self.max_iters or (self.att_type == 0 and sim >= self.th) or (
                    self.att_type == 1 and sim <= self.th):
                rewards[i] = sim

        return rewards

    def get_rewards_from_current_state(self, model, pool):
        possible_actions = self.get_actions_from_state(model, pool)
        new_states = self.apply_multiple_actions(possible_actions, pool)

        rewards = self.rewards_from_states(new_states, model)

        return rewards

    @staticmethod
    def parallel_take_action(parameters):
        state = parameters[0]
        action = parameters[1]

        new_state = state.get_new_state_from_action(action)

        return new_state
