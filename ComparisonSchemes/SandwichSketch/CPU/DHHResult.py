import pandas as pd
import os
import re
import sys
import csv

def multi_sketch_result(algorithm, memory, node_num, large_node_param, rate, is_disjoint): 
    memory = memory * 1000
    folder = "./results/"
    files = os.listdir(folder)

    Datasets = ["CAIDA"]

    dataset = Datasets[0]

    result = []
    DHH_pattern = "DHH-" + dataset + "-" + algorithm + "-" + str(memory) + "-" + str(node_num) + "-" + str(large_node_param) + "-" + str(rate) + "-" + str(is_disjoint) + "-.*.csv"
    DHH_files = []

    for file in files:
        if re.match(DHH_pattern, file):
            DHH_files.append(file)
        
    if len(DHH_files) != 1:
        print("Multiple DHH Files")
        print(DHH_files)
        
    DHH_file = DHH_files[0]
    cin = open(folder + DHH_file, "r")
    csv_reader = csv.reader(cin)
        
    metrics = {}
    temp_key = -1
        
    for row in csv_reader:
        if len(row) == 0:
            continue

        if row[0] == 'SpecialSrcIPs':
            temp_key = 7
            if metrics.get(temp_key) != None:
                print("Key Error")
            metrics[temp_key] = [0 for i in range(6)]
        elif row[0] == 'key-type':
            temp_key = int(row[1])
            if metrics.get(temp_key) != None:
                print("Key Error")
            metrics[temp_key] = [0 for i in range(6)]
        
        if temp_key < 0:
            print("temp_key error")
        if row[0] == 'realHH':
            metrics[temp_key][0] = int(row[1])
        if row[0] == 'estHH':
            metrics[temp_key][1] = int(row[1])
        if row[0] == 'bothHH':
            metrics[temp_key][2] = int(row[1])
        if row[0] == 'aae':
            metrics[temp_key][3] = float(row[1])
        if row[0] == 'are':
            metrics[temp_key][4] = float(row[1])
        if row[0] == 'Thp':
            metrics[temp_key][5] = float(row[1])

    specialDict = {}

    for i in range(1, 8):
        realHH, estHH, bothHH, aae, are = 0, 0, 0, 0, 0
        dict = {}
        for key in metrics.keys():
            if i == 7:
                realHH = metrics[key][0]
                estHH = metrics[key][1]
                bothHH = metrics[key][2]
                aae = metrics[key][3]
                are = metrics[key][4]
            elif i >= key:
                realHH += metrics[key][0]
                estHH += metrics[key][1]
                bothHH += metrics[key][2]
                aae += metrics[key][3]
                are += metrics[key][4]
        
        # print("Result for Key = " + str(i))
        # print("CR: " + str(bothHH / realHH))
        # print("PR: " + str(bothHH / estHH))
        # print("AAE: " + str(aae / bothHH))
        # print("ARE: " + str(are / bothHH))
        
        dict["CR"] = bothHH / realHH
        dict["PR"] = bothHH / estHH
        dict["F1"] = (2*dict["CR"]*dict["PR"]) / (dict["CR"]+dict["PR"])
        dict["AAE"] = aae / bothHH
        dict["ARE"] = are / bothHH
        if i == 7:
            specialDict = dict
        else:
            result.append(dict)

    return result, specialDict

if __name__ == "__main__":
    memory = int(sys.argv[1])
    node_num = int(sys.argv[2])
    large_node_param = int(sys.argv[3])
    rate = float(sys.argv[4])
    is_disjoint = int(sys.argv[5])


    MultiAlgs = ["Ours", "CocoSketch", "USSHeap"]
    AllAlgs = ["Ours", "CocoSketch", "USSHeap"]


    all_result = {}
    spcial_result = {}

    for name in MultiAlgs:
        all_result[name], spcial_result[name] = multi_sketch_result(name, memory, node_num, large_node_param, rate, is_disjoint)

    ## Metric
    CR_result = []
    for i in range(0,6):
        tmp = []
        for alg in AllAlgs:
            tmp.append(all_result[alg][i]["CR"])
        CR_result.append(tmp)
        
    CR_data = pd.DataFrame(CR_result, columns=AllAlgs, index=[i for i in range(1,7)])
    print("Recall:")
    print(CR_data)

    PR_result = []
    for i in range(0,6):
        tmp = []
        for alg in AllAlgs:
            tmp.append(all_result[alg][i]["PR"])
        PR_result.append(tmp)
        
    PR_data = pd.DataFrame(PR_result, columns=AllAlgs, index=[i for i in range(1,7)])
    print("Precision:")
    print(PR_data)

    F1_result = []
    for i in range(0,6):
        tmp = []
        for alg in AllAlgs:
            tmp.append(all_result[alg][i]["F1"])
        F1_result.append(tmp)
        
    F1_data = pd.DataFrame(F1_result, columns=AllAlgs, index=[i for i in range(1,7)])
    print("F1 Score:")
    print(F1_data)

    AAE_result = []
    for i in range(0,6):
        tmp = []
        for alg in AllAlgs:
            tmp.append(all_result[alg][i]["AAE"])
        AAE_result.append(tmp)
        
    AAE_data = pd.DataFrame(AAE_result, columns=AllAlgs, index=[i for i in range(1,7)])
    print("AAE:")
    print(AAE_data)

    ARE_result = []
    for i in range(0,6):
        tmp = []
        for alg in AllAlgs:
            tmp.append(all_result[alg][i]["ARE"])
        ARE_result.append(tmp)
        
    ARE_data = pd.DataFrame(ARE_result, columns=AllAlgs, index=[i for i in range(1,7)])
    print("ARE:")
    print(ARE_data)

    spcial_data = pd.DataFrame(spcial_result)
    print("SpecialSrcIPs:")
    print(spcial_data)
