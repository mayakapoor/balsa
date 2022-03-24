from palm import Palm
import time
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report,confusion_matrix ,ConfusionMatrixDisplay, cohen_kappa_score
from argparse import ArgumentParser
import matplotlib.pyplot as plt
import glob
import os
import seaborn as sns
import statistics
from imblearn.under_sampling import RandomUnderSampler

def extract_hash_values(df):
    return df[["src_port","dst_port","t_proto","dsfield","ip_flags","length","payload"]]
    #return df[["t_proto","dsfield","ip_flags","length","payload"]]

if __name__ == "__main__":
    parser = ArgumentParser(description="Process pcap file and integer data.")
    parser.add_argument("-dataFolder", help="The data root folder.")
    args = parser.parse_args()
    os.chdir(args.dataFolder)
    path = os.getcwd()
    list_X = []
    list_y =[]
    for root,dirs,files in os.walk(path):
        csv_files = glob.glob(os.path.join(root, "*.csv"))
        for f in csv_files:
            data = pd.read_csv(f, delimiter=",", dtype=str)
            #data.dropna(inplace=True)
            # data = data.sample(100, random_state=4, replace=True)
            #print(data)
            data_X = extract_hash_values(data)
            data_y = data[["d_proto"]]
            list_X.append(data_X)
            list_y.append(data_y)
    X = pd.concat(list_X, ignore_index=True)
    y = pd.concat(list_y, ignore_index=True)
    #y["d_proto"] = y["d_proto"].replace(["ftp", "ftpdata", "bittorrent", "dns", "http", "xmpp", "sip", "h225", "mgcp", "rtp", "dhcp", "ntp", "nbns", "ssh", "telnet", "gprs", "pptp", "ldap", "smb", "pop", "smtp", "imap", "gquic", "ssdp", "rtcp"], "non-tls")

    print(len(X))
    print("Data count before sampling " , len(y))
    rus = RandomUnderSampler(random_state=888)
    X, y = rus.fit_resample(X, y)
    print("Data count after sampling " , len(y))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.5, random_state=4, stratify=y)
    forest = Palm(64)
    print("training phase...")
    labels = y_train["d_proto"].unique()
    print(labels)
    start = time.time()
    for label in labels:
        curr = X_train.loc[y_train.loc[y_train["d_proto"] == label].index.tolist()]
        forest.add_bucket(curr, label)
    print("training time in seconds: " + str(time.time() - start))
    forest.finalize()
    num_votes = 10

    total = 0
    MBs = 0
    for i, row in X_test.iterrows():
        total = total + int(row["length"])
        if total > 1000000:
            MBs += total/1000000
            total = 0

    print("testing phase...")
    classification_time = []
    start = time.time()
    y_pred = forest.query_batch(X_test, num_votes)
    end = time.time()
    print("ms per classification: " + str((((end-start)/len(y_test))*1000)))
    print("number of test samples: " + str(len(y_test)))
    print("Mb/s: " + str((MBs*8)/(end-start)))
    print("accuracy: " + str(accuracy_score(y_pred, y_test)))
    print("cohen kappa score: " + str(cohen_kappa_score(y_test, y_pred)))
    print("classification report: \n"+ classification_report(y_test, y_pred))
    cm = confusion_matrix(y_test["d_proto"].tolist(), y_pred)
    print(len(y_test["d_proto"].tolist()))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
    fig, ax = plt.subplots(figsize=(15, 15))
    disp.plot(ax=ax, cmap="YlOrRd")
    plt.show()
    plt.savefig('../../images/confusion_matrix_vpn_{}.png'.format("d_proto"))
