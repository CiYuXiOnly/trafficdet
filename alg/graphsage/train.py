import argparse
import numpy as np
import time
import random
import torch
import torch.nn as nn
from torch.autograd import Variable
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from alg.graphsage.loader import load_sage
from alg.graphsage.model import GraphSage

np.random.seed(1)
random.seed(1)
data_class = {"UNSW-NB15":10}
data_lr = {"UNSW-NB15":0.007}
test_size = {"UNSW-NB15":210000}

def fit(args, data_path, model_save_path, epoch_num):
    data = args.dataset
    binary = args.binary
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    enc2, edge_feat, label, node_map, adj = load_sage(data_path, binary)
    model = GraphSage(data_class[data], enc2, edge_feat, node_map, adj)
    # loss and optimizer
    loss_fn = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(filter(lambda p: p.requires_grad,
                                            model.parameters()),
                                 lr=data_lr[data])

    # train test split
    num_edges = len(edge_feat)
    train_val, test = train_test_split(np.arange(num_edges), test_size=test_size[data], stratify=label)
    train, val = train_test_split(train_val, test_size=5000, stratify=label[train_val])

    times = []
    trainscores = []
    valscores = []

    for epoch in range(epoch_num):
        print("Epoch: ", epoch)
        random.shuffle(train)
        epoch_start = time.time()
        for batch in range(int(len(train) / 500)):  # batches in train data
            batch_edges = train[500 * batch:500 * (batch + 1)]  # 500 records per batch
            start_time = time.time()
            # training
            model.train()
            # forward(self, edge_idx)
            output, _ = model(batch_edges)
            train_output = output.data.numpy()
            acc_train = f1_score(label[batch_edges],
                                    train_output.argmax(axis=1),
                                    average="weighted")
            loss = model.loss(batch_edges,
                                    Variable(torch.LongTensor(label[np.array(batch_edges)])))
                
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            end_time = time.time()
            times.append(end_time - start_time)
            trainscores.append(acc_train)

            print('batch: {:03d}'.format(batch + 1),
                  'loss_train: {:.4f}'.format(loss.item()),
                  'acc_train: {:.4f}'.format(acc_train.item()),
                  'time: {:.4f}s'.format(end_time - start_time))

            if batch >= 179:
                break
        epoch_end = time.time()

        # save model
        # 保存模型参数  
        torch.save(model.state_dict(), model_save_path)     
        
        # Validation
        model.eval()
        acc_val, loss_val, val_output = predict_(model, label, loss_fn, val)
        valscores.append(acc_val)

        print('loss_val: {:.4f}'.format(loss_val),
              'acc_val: {:.4f}'.format(acc_val.item()),
              'average batch time: {:.4f}s'.format(np.mean(times)),
              'epoch time: {:.2f}min'.format((epoch_end - epoch_start)/60.0))

    # Testing
    acc_test, loss_test, predict_output = predict_(model, label, loss_fn, test)
    print("Test set results:", "loss= {:.4f}".format(loss_test),
          "accuracy= {:.4f}".format(acc_test.item()),
          "label acc=", f1_score(label[test], predict_output, average=None))


def predict_(model, label, loss_fn, data_idx):
    predict_output = []
    loss = 0.0
    # emb = []
    for batch in range(int(len(data_idx) / 500)):
        batch_edges = data_idx[500 * batch:500 * (batch + 1)]
        batch_output, _ = model(batch_edges)

        batch_output = batch_output.data.numpy().argmax(axis=1)
        batch_loss = model.loss(batch_edges,
                            Variable(torch.LongTensor(label[np.array(batch_edges)])))
       
        predict_output.extend(batch_output)
        loss += batch_loss.item()
        # emb.append(embed)
    loss /= batch + 1
    acc = f1_score(label[data_idx], predict_output, average="weighted")
    # emb = torch.stack(emb).view(5000, -1)
    return acc, loss, predict_output


# -----------------------------------------------------------------------------

if __name__ == '__main__':

    DATASET = ['UNSW-NB15']
    isbinary = [1, 0]

    p = argparse.ArgumentParser()
    p.add_argument('--dataset',
                   help='Experimental dataset.',
                   type=str,
                   default='UNSW-NB15',
                   choices=DATASET)
    p.add_argument('--binary',
                   help='Perform binary or muticlass task',
                   type=int,
                   choices=isbinary,
                   default=1)

    # Parse and validate script arguments.
    args = p.parse_args()
    
    data_path = "./alg/dataset/" + args.dataset + "/graphsage/data.csv"
    model_save_path = "./alg/graphsage/model.pth"

    print('num_class: {}'.format(data_class[args.dataset]))
        
    # Training and testing
    fit(args, data_path, model_save_path, epoch_num=1)
