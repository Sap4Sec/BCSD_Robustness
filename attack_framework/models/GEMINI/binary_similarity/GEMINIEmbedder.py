import os
import sys
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
stderr = sys.stderr
sys.stderr = open(os.devnull, 'w')

import tensorflow as tf

sys.stderr = stderr
tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)


class GEMINIEmbedder:

    def __init__(self, model_file):
        self.model_file = model_file
        self.session = None
        self.loadmodel()
        self.graph = tf.get_default_graph()
        self.x_1 = None
        self.adj_1 = None
        self.x_2 = None
        self.adj_2 = None
        self.emb = None

    def loadmodel(self):
        sess = tf.Session(config=tf.ConfigProto(intra_op_parallelism_threads=25))
        checkpoint_dir = os.path.abspath(self.model_file)
        saver = tf.train.import_meta_graph(os.path.join(checkpoint_dir, "model.meta"))
        tf.global_variables_initializer().run(session=sess)
        saver.restore(sess, os.path.join(checkpoint_dir, "model"))
        self.session = sess
        return

    def get_tensor(self):
        self.x_1 = self.graph.get_tensor_by_name("x_1:0")
        self.adj_1 = self.graph.get_tensor_by_name("adj_1:0")
        self.x_2 = self.graph.get_tensor_by_name("x_2:0")
        self.adj_2 = self.graph.get_tensor_by_name("adj_2:0")
        self.emb = tf.nn.l2_normalize(
            tf.squeeze(self.graph.get_tensor_by_name('MeanField1/MeanField1_graph_embedding:0'), axis=1), axis=1,
            name="oute1")

    def embedd(self, matrice_input, nodi_input):
        out_embedding = self.session.run(self.emb, feed_dict={
            self.x_1: nodi_input,
            self.adj_1: matrice_input,
            self.x_2: nodi_input,
            self.adj_2: matrice_input})
        return out_embedding