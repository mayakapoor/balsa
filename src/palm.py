import re
import random
import numpy as np
import pandas as pd
from collections import defaultdict
from datasketch import MinHash, MinHashLSHForest
from sklearn.feature_extraction.text import TfidfVectorizer

class Bucket:
    def __init__(self, name, data):
        self.name = name
        self.useTFIDF = False
        try:
            tfIdfVectorizer = TfidfVectorizer(use_idf=True, stop_words=None)
            tfIdf = tfIdfVectorizer.fit_transform(data["payload"].values.astype('U'))
            df = pd.DataFrame(tfIdf[0].T.todense(), index=tfIdfVectorizer.get_feature_names_out(), columns=["TF-IDF"])
            df = df.sort_values('TF-IDF', ascending=False)
            df_mask = df["TF-IDF"] > 0.01
            filtered_df = df[df_mask]
            self.relevant_tokens = filtered_df.iloc[:,0]
            self.useTFIDF = True
        except ValueError:
            return

class Palm:
    def __init__(self, perms):
        self.my_forest = MinHashLSHForest(num_perm=perms)
        self.my_lookup_table = {}
        self.my_buckets = {}
        self.my_num_perms = perms
        self.my_curr_index = 0

    def make_tokens_for_test(self, row):
        tokens = row.values.tolist()[:-1] + str(row["payload"]).split()
        return tokens

    def make_tokens(self, row, label):
        tokens = row.values.tolist()[:-1]
        payload = str(row["payload"]).split()
        for token in payload:
            if self.my_buckets[label].useTFIDF and token in self.my_buckets[label].relevant_tokens:
                tokens.append(token)
            elif not self.my_buckets[label].useTFIDF:
                tokens.append(token)
        return tokens

    def add_bucket(self, data, label):
        self.my_buckets[label] = Bucket(label, data)

        minhash = []

        for i, row in data.iterrows():
            m = MinHash(num_perm=self.my_num_perms)
            #uncomment for TFIDF usage
            #tokens = self.make_tokens(row, label)
            tokens = self.make_tokens_for_test(row)
            for token in tokens:
                m.update(str(token).encode('utf-8'))
            minhash.append(m)

        for m in minhash:
            # add the hash with its index to the forest
            self.my_forest.add(self.my_curr_index, m)
            # add the bucket to the lookup table
            self.my_lookup_table[self.my_curr_index] = label
            self.my_curr_index += 1

    def finalize(self):
        self.my_forest.index()

    def query(self, row, num_results):
        m = MinHash(num_perm=self.my_num_perms)
        for token in self.make_tokens_for_test(row):
            m.update(str(token).encode('utf-8'))
        arr = np.array(self.my_forest.query(m, num_results))
        counts = defaultdict()
        for ret in arr:
            bucket = self.my_lookup_table[ret]
            if bucket in counts:
                counts[bucket] += 1
            else:
                counts[bucket] = 1
        if len(counts) == 0:
            return self.my_lookup_table[random.randint(0, self.my_curr_index)]
        return max(counts, key=counts.get)
