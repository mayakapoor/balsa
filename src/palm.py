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

    def hash(self, data):
        tokens = []
        for i, row in data.iterrows():
            raw_tokens = self.make_tokens_for_test(row)
            encoded_tokens = []
            for token in raw_tokens:
                encoded_tokens.append(str(token).encode('utf-8'))
            tokens.append(encoded_tokens)
        return MinHash.bulk(tokens, num_perm=self.my_num_perms)

    def add_bucket(self, data, label):
        self.my_buckets[label] = Bucket(label, data)

        minhashes = self.hash(data)

        for m in minhashes:
            # add the hash with its index to the forest
            self.my_forest.add(self.my_curr_index, m)
            # add the bucket to the lookup table
            self.my_lookup_table[self.my_curr_index] = label
            self.my_curr_index += 1

    def finalize(self):
        self.my_forest.index()

    def query_batch(self, data, num_results):
        minhashes = self.hash(data)
        y_pred = []
        for m in minhashes:
            arr = np.array(self.my_forest.query(m, num_results))
            counts = defaultdict()
            for ret in arr:
                bucket = self.my_lookup_table[ret]
                if bucket in counts:
                    counts[bucket] += 1
                else:
                    counts[bucket] = 1
            if len(counts) == 0:
                y_pred.append(self.my_lookup_table[random.randint(0, self.my_curr_index-1)])
            else:
                y_pred.append(max(counts, key=counts.get))
        return y_pred

    def query(self, row, num_results):
        m = MinHash(num_perm=self.my_num_perms)
        m.update_batch(str(token).encode('utf-8') for token in self.make_tokens_for_test(row))
        #for token in self.make_tokens_for_test(row):
        #    m.update(str(token).encode('utf-8'))
        arr = np.array(self.my_forest.query(m, num_results))
        counts = defaultdict()
        for ret in arr:
            bucket = self.my_lookup_table[ret]
            if bucket in counts:
                counts[bucket] += 1
            else:
                counts[bucket] = 1
        if len(counts) == 0:
            return self.my_lookup_table[random.randint(0, self.my_curr_index-1)]
        return max(counts, key=counts.get)
