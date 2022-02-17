import csv
import os.path
import subprocess
import time
import datetime
import os
import sys
import shutil
from csv import DictWriter

from numpy import string_
import matplotlib
import pickle5 as pickle
matplotlib.use('Agg')

import numpy as np
import urllib,base64
import matplotlib.pyplot as plt
import matplotlib.pyplot as pltt
plt.ioff()
import io
import csv
import pandas as pd
from django.http import HttpResponse
from django.shortcuts import render
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from keras.models import load_model
from scapy.all import *


from keras.models import load_model
from keras.preprocessing.image import load_img
from keras.preprocessing.image import img_to_array
from scapy.packet import Padding
from scapy.utils import rdpcap
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether
from csv import DictWriter
from scapy.compat import raw
from scapy.all import *
import numpy


# Create your views here.
def norm(x,v):
  return x/v
def tostring1(x):
  return '{:.2f}'.format(x)

def webpage1(request):
   
    csvfile = "E:\\ads\\toolV1.2\\mysite\\csvOfLinks\\linksCsv.csv"
    data = pd.read_csv(csvfile)
    
    style = '<style>.dataframe tr { text-align: left; }</style>'
    data_html = data.to_html(justify='left')
    context = {'loaded_data': data_html}
    return render(request, "page1.html", context)

def webpage2(request):
    result = request.GET["cars"].split(",")[1]
    linkNumberr = request.GET["cars"].split(",")[0]
    linkNumber = linkNumberr.replace(" ","")
    #data = pd.read_csv("links.csv")
    i=0
    BPS_list=[]
    while (i < 1):
        #print(str(data['id'][i]) + ": " + str(data['Links'][i]))
        filename = linkNumber
        urlF = str(result)
        amount = 1
        link100_url = urlF
        link100_duration = 10
        filename = harvest_video(amount,filename,link100_url,link100_duration)
        print(filename)
        i+=1
    ips=[]
    ipsSet =set((p[IP].src, p[IP].dst,p[IP].proto) for p in PcapReader(filename) if IP in p)
    mostOccuredIp=""
    if(len(ipsSet)<=2):

        for i in ipsSet:
            ipss=i
            break
        mostOccuredIp = ipss[0]
        if mostOccuredIp == "172.16.100.7":
            mostOccuredIp = ipss[1]
    else:
        uniqueB=[]
        for i in ipsSet:
            print(i)
            uniqueB.append(i[1])
            
        from collections import Counter
        occurence_count = Counter(uniqueB)
        mostOccuredIp = occurence_count.most_common(1)[0][0]
        
    print("ip is", mostOccuredIp)
    with open("E:\\ads\\toolV1.2\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        file = filename
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
        BPS_list=bytes_per_second['frame.len'][0:120]
        
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 120:
            print("len is less")
            diff = 120- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        BPS_list.append(linkNumberr)
        writer.writerow(BPS_list)
    #bytes per second 
    plt.close()
    plt.cla()
    plt.clf()
    x = []
    y = []
    array = []
    with open('E:\\ads\\toolV1.2\\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv','r') as csvfile:
        plots = csv.reader(csvfile, delimiter = ',')
        print(plots) 
        for col in plots:
            col = col[0:-1]
            array = col
            for i in range(len(col)):
                print(col[i])
                x.append(i)
                y.append(int(col[i]))
    plt.rcParams["figure.figsize"] = (7,2)
    plt.rcParams['figure.dpi'] = 600
    plt.bar(x, y, color = 'black', width = 0.72 )
    plt.xlabel('Time(s)')
    plt.ylabel('Bytes per second')
    plt.title('Bytes per second')
    import urllib,base64
    plt.plot()
    fig=plt.gcf()
    buf = io.BytesIO()
    fig.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri = urllib.parse.quote(string)
    df =  pd.DataFrame (array, columns = ['column_name'])
    df['column_name'] = df['column_name'].astype(int)
    mean = df['column_name'].mean()
    std = df['column_name'].std()
    firstQuartile  =  df.column_name.quantile([0.25]).to_string(index=False)
    median = df.column_name.quantile([0.50]).to_string(index=False)
    secondQuartile =  df.column_name.quantile([0.75]).to_string(index=False)
    plt.close()

    #bytes per peak
    xx = []
    yy = []

    sum=0
    with open('E:\\ads\\toolV1.2\\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv','r') as csvfile:
        plots = csv.reader(csvfile, delimiter = ',')
        print(plots)
        for col in plots:
            print(col)
            col = col[0:-1]
            
            for i in range(len(col)):
                
                if i<len(col)-1:   
                    if int(col[i+1])!= 0 :
                        sum=sum+int(col[i])
                    else:
                        sum=sum+int(col[i])
                        if sum!=0:
                            yy.append(sum)
                            
                            sum=0
                else:
                    sum=sum+int(col[i])
                    yy.append(sum)
    xx=range(1,len(yy)+1)   

    plt.rcParams["figure.figsize"] = (7,2)
    
    plt.rcParams['figure.dpi'] = 600
    plt.bar(xx,yy, color = 'black', width = 0.72 )
    plt.xlabel('Time(s)')
    plt.ylabel('Bytes per Peak')
    plt.title("Bytes per Peak")
    plt.plot()
    figgggggg=plt.gcf()
    buf = io.BytesIO()
    figgggggg.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri5 = urllib.parse.quote(string)
    BPS_list.clear()
    plt.close()

    
    #packets per second 
    with open(r"E:\\ads\\toolV1.2\\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
           
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        file = filename
        newBPS_list = []
        newBPS_list2= []
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        packet_per_second=source_address.resample("s", on='frame.time_epoch').count()
        BPS_list=packet_per_second['frame.len'][0:120]
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 120:
            print("len is less")
            diff = 120- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        plt.bar(range(len(BPS_list)),BPS_list,color = 'black', width = 0.72)
        plt.rcParams["figure.figsize"] = (7,2)
        plt.rcParams['figure.dpi'] = 600
        plt.title('Packets per second')
        plt.xlabel('Time(s)')
        plt.ylabel('Packet per second')
        plt.plot()
        figg=plt.gcf()
        buf = io.BytesIO()
        figg.savefig(buf,format='png')
        buf.seek(0)
        string = base64.b64encode(buf.read())
        uri1 = urllib.parse.quote(string)
        BPS_list.clear()
        plt.close()
    #instantaneous graph
    with open(r"E:\\ads\\toolV1.2\\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        file = filename
        newBPS_list = []
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
            
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        bytes_per_second=source_address.resample("100ms", on='frame.time_epoch').sum()
    
        BPS_list=bytes_per_second['frame.len'][0:1200]
        
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 1200:
            print("len is less")
            diff = 1200- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        for data in BPS_list:
            temp = (data/1024)
            newBPS_list.append(temp)
        plt.rcParams["figure.figsize"] = (7,2)
        plt.rcParams['figure.dpi'] = 600
        
        plt.plot(newBPS_list)

        plt.title('Bytes per 100ms')
        plt.xlabel('Time(ms)')
        plt.ylabel('Instantaneous data (KB)')
        plt.plot()
        figgg=plt.gcf()
        buf = io.BytesIO()
        figgg.savefig(buf,format='png')
        buf.seek(0)
        string = base64.b64encode(buf.read())
        uri2 = urllib.parse.quote(string)
        BPS_list.clear()
        plt.close()

    #short on and off cycle
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        newBPS_list = []
        newBPS_list2= []
        file =  filename
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
        BPS_list=bytes_per_second['frame.len'][0:120]
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 120:
            print("len is less")
            diff = 120- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        for data in BPS_list:
            temp = (data/1024)/1024
            newBPS_list.append(temp)
        cdf = np.cumsum(newBPS_list)
    plt.plot(cdf)
    plt.title('Data downloaded')
    plt.xlabel('Time(s)')
    plt.ylabel('Download Amount (MB)')
    plt.rcParams["figure.figsize"] = (7,2)
    plt.rcParams['figure.dpi'] = 600
    figggg=plt.gcf()
    buf = io.BytesIO()
    figggg.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri3 = urllib.parse.quote(string)
    BPS_list.clear()
    plt.close()
    BPS_list.clear()

    #normalized 
    fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
    newBPS_list = []
    newBPS_list2= []
    file =  filename
    temp=read_pcap(file, fields, timeseries=True, strict=True)
    temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')  
    source_address=temp[temp["ip.dst"] == mostOccuredIp]
    bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
    BPS_list=bytes_per_second['frame.len'][0:120]
    BPS_list = list(map(_replaceitem, BPS_list))
    lenBPS = len(BPS_list)
    if lenBPS < 120:
        print("len is less")
        diff = 120- lenBPS
        for d in range(diff):
            BPS_list.append(0)
    for data in BPS_list:
        temp = (data/1024)/1024
        newBPS_list.append(temp)
    normalized = (cdf-min(cdf))/(max(cdf)-min(cdf))
    plt.plot(normalized)
    plt.title('Cumulative downloaded data')
    plt.xlabel('Time(s)')
    plt.ylabel('CDF')
    plt.rcParams["figure.figsize"] = (7,2)
    plt.rcParams['figure.dpi'] = 600
    figgggg=plt.gcf()
    buf = io.BytesIO()
    figgggg.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri4 = urllib.parse.quote(string)
    BPS_list.clear()
    plt.close()
    BPS_list.clear()


    plt.close()
    plt.cla()
    plt.clf()
    #model predication
    #------------------- df  = list of BPS -----------------
    BPS_list=[]
    with open("E:\\ads\\toolV1.2\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        file = filename
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
        BPS_list=bytes_per_second['frame.len'][0:120]
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 120:
            print("len is less")
            diff = 120- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        BPS_list.append(linkNumberr)
        writer.writerow(BPS_list)
    array = BPS_list[0:120]

    #dict of links
    linksDict = {"link1":"Learn Object Oriented Programming in 10 minutes (Java)","link111":"Arslan Ash vs Knee - EVO 2019 Grand Finals - Tekken 7","link112":"How To Make Marble Cake At Home in Urdu I Marble Cake Recipe I No Oven Cake Recipe I Marble Tea Cake","link113":"Mozzarella Cheese Recipe By ijaz Ansari | How To Make Mozzarella Cheese At Home | No Rennet |","link114":"Extra Crispy Fried Chicken Recipe By Food Fusion (Ramzan Special)","link115":"10 Most Expensive Things Dwayne The Rock Johnson Owns - MET Ep 14","link116":"Shahid Afridi Home Tour | Exclusive Video","link117":"Ek Sharabi Jo Sharab Se Roza Iftar Krta Tha | Latest Ramadan Bayan by Maulana Tariq Jameel 2017","link118":"Daniel Bryan & Roman Reigns vs. Seth Rollins Big Show Kane & J&J Security: Raw February 9 2015","link119":"Spintop Snipers | Amazing Top Trick Shots!","link120":"Random Acts of Kindness - Faith In Humanity Restored #3","link121":"Sony - World's First Smartphone To Do This","link122":"AVENGERS ENDGAME Becoming Fat Thor Behind the Scenes Bonus Clip (2019) Chris Hemsworth Move HD","link123":"ScaleTrains BNSF HO Scale Dash 9 C44-9W Unboxing","link124":"Xiaomi Mi Mix Alpha Impressions: The Wraparound Display!","link125":"Shan-e-Iftar - Shan E Dastarkhwan [Chicken Parmesan] - 23rd April 2021 - Chef Farah","link126":"Latest Trouser Design 2021 | Capri Design 2021 | Plazo Pant Design","link128":"VW Amarok Tackling Gunshot Creek Sept 2015","link129":"Eau De Bean | Mr Bean Cartoon Season 3 | NEW FULL EPISODE | Season 3 Episode 12 | Mr Bean Official","link2":"Why You Shouldn’t Learn Python In 2021","link3":"10 LATEST TECHNOLOGY INVENTIONS ▶ Smart Vehicle You Must See","link31":"Can My Water Cooled Raspberry Pi Cluster Beat My MacBook?","link32":"LIFE IN RAMZAN! | COMEDY VIDEO","link33":"Russell Shakib & Malan Join in | Zero Tolerance required for PSL Protocols","link34":"TensorFlow.js Quick Start","link35":"you need to learn Virtual Machines RIGHT NOW!! (Kali Linux VM Ubuntu Windows)","link36":"Coding Interview | Software Engineer @ Bloomberg (Part 1)","link38":"Amazing Brathwaite 100! | West Indies v New Zealand - Match Highlights | ICC Cricket World Cup 2019","link39":"Ferocious Dinosaur Moments | Top 5 | BBC Earth","link40":"10 Latest NEW TECH GADGETS AND INVENTIONS 2020 | Available On Amazon | You Can Buy in ONLINE STORE","link41":"Ranking push of my team's OP Play video | Many Hackers | PUBG MOBILE","link85":"AIRPLANE Bean | Bean Movie | Funny Clips | Mr Bean Official","link86":"Mini LED cube with 54 pixel WiFi & gyroscope | SMT hotplate soldering | Pikocube v2.0","link87":"ASMR Video | Build Modern Glass Elevator For Underground And Rooftop Infinity Swimming Pool","link88":"NEW BEST LANDING IN MILITARY BASE","link89":"Random Facts Around The World | Part 57 | Urdu / Hindi","link90":"How THANOS Knew TONY In Avengers: Infinity War? | Super Questions Ep. 5 | Super Access","link91":"Data Center NETWORKS (what do they look like??) // FREE CCNA // EP 7","link92":"New Ghar Saman Shift Karna Shuru Kar diya","link93":"2v4 CLUTCH FOR THE WWCD • PMPL FINALS • 2 MAN CHICKEN DINNER •","link94":"MAKING A SNEAKER ROOM IN MY NEW HOUSE!","link95":"5 Richest Kids Of Pakistan | TOP X TV","link96":"Levels of Ultra Instinct (1% - 50% - 100%)"}
    
    # ensemble list
    ensembleList = []

    #link name for selected link number
    selectedLinkNumberName = linksDict[linkNumberr.lower().replace(" ", "")]
    
    #BPS model
    predict_name = BPSModel(array)
    ensembleList.append(predict_name)
    print("predicted by BPS is ", predict_name)
    predict_name = linksDict[predict_name]

    #detect BPS - Classes (VPN vs NonVPN)
    #predict_name_BPS_Classes = BPSClassesVPNvsNonVPN(array)
    #print("predicted by BPS with classes is ", predict_name_BPS_Classes)
    #predict_name_BPS_Classes = linksDict[predict_name_BPS_Classes]

    #BPS - Without Classes (VPN vs NonVPN)
    predict_name_BPS_Without_Classes = BPSWithoutClassesVPNvsNonVPN(array)
    print("predicted by BPS without classes is ", predict_name_BPS_Without_Classes)
    
    #DF model 
    predict_name_DF = testingWithFingerprint(array)
    ensembleList.append(predict_name_DF)
    print("predicted by df is ", predict_name_DF)
    predict_name_DF = linksDict[predict_name_DF]
    
    #PAT model
    PATBpsList = generate_PAT(filename,linkNumberr)
    predict_name_PAT = preditWithPATFingerprint(PATBpsList, linkNumberr)
    ensembleList.append(predict_name_PAT)
    print("predicted by PAT is ", predict_name_PAT)
    predict_name_PAT = linksDict[predict_name_PAT]
    
    #ensemble
    predict_name_ensemble = ensemble(ensembleList)
    print(ensembleList)
    print("predicted by ensemble is ", predict_name_ensemble)
    if predict_name_ensemble != "Ensemble failed":
        predict_name_ensemble = linksDict[predict_name_ensemble]

    #flowpic
    predict_name_FP,uriFP = testingWithFlowpic(filename)
    print("predicted by fp is ", predict_name_FP)
    predict_name_FP = linksDict[predict_name_FP] 
    plt.close()
    plt.cla()
    plt.clf()

    return render(request,"page2.html",{'cars':result,'data':uri,"mean":mean,"std":std,"qur1":firstQuartile,"median":median,"qur2":secondQuartile,"packetsPerSecond":uri1,"Instantaneous":uri2,"shortOnOffCycle":uri3,"normalized":uri4,"bytesPerPeak":uri5,"flowPicImg":uriFP,"linkNumber":selectedLinkNumberName,"predictedName":predict_name,"bpsWithoutClasses":predict_name_BPS_Without_Classes,"DF":predict_name_DF,"FP":predict_name_FP,"PAT":predict_name_PAT,"ensemble":predict_name_ensemble})

def BPSModel(array):

    #BPS model
    model_path=r"E:\ads\models\BPS model\NonVPN_04-01-2022-10-46_9830494.h5"       
    model = load_model(model_path)
    
    data = ""
    with open(r"E:\ads\models\BPS model\NonVPN_04-01-2022-10-46_9830494.pkl", "rb") as fh:
      data = pickle.load(fh)
    l_temp=(data)
    x = []
    df =  pd.DataFrame (array, columns = ['column_name'])
    df['column_name'] = df['column_name'].astype(int)
    #name = str(df[i,121:].values.tolist())
    x = df['column_name'] #

    v=int(model_path.split("_")[-1].split(".")[0])

    x1=np.vectorize(norm)(x,v)
    labels = np.asarray(l_temp, dtype = np.int8)
    x3 = x1.reshape(1,120,1)
    y_pred1 = model.predict(x3)
    l_temp.loc[-1]=y_pred1[0]
    predict_name = l_temp.loc[-1].idxmax()
    return predict_name

def BPSClassesVPNvsNonVPN(array):
    
    model = load_model(r'E:\\ads\\modelfiles\\BPS - Classes (VPN vs NonVPN)(pending)\\Classes.h5')
    l_temp=pd.read_pickle(r'E:\\ads\\modelfiles\\BPS - Classes (VPN vs NonVPN)(pending)\\Classes.pkl')
    x = []
    df =  pd.DataFrame (array, columns = ['column_name'])
    df['column_name'] = df['column_name'].astype(int)
    #name = str(df[i,121:].values.tolist())
    x = df['column_name'] #
    name  = "link1"
    v=4459355
    x1=np.vectorize(norm)(x,v)

    labels = np.asarray(l_temp, dtype = np.int8)
    x3 = x1.reshape(1,120,1)
    y_pred1 = model.predict(x3)

    l_temp.loc[-1]=y_pred1[0]

    predict_name_BPS_Classes = l_temp.loc[-1].idxmax()
    return predict_name_BPS_Classes

def BPSWithoutClassesVPNvsNonVPN(array):
    model = load_model(r'E:\\ads\\modelfiles\\BPS - Without Classes (VPN vs NonVPN)(pending)\\Without_Classes.h5')
    l_temp=pd.read_pickle(r'E:\\ads\\modelfiles\\BPS - Without Classes (VPN vs NonVPN)(pending)\\Without Classes.pkl')
    x = []
    df =  pd.DataFrame (array, columns = ['column_name'])
    df['column_name'] = df['column_name'].astype(int)
    #name = str(df[i,121:].values.tolist())
    x = df['column_name'] #
    name  = "link1"
    v=4459355
    x1=np.vectorize(norm)(x,v)

    labels = np.asarray(l_temp, dtype = np.int8)
    x3 = x1.reshape(1,120,1)
    y_pred1 = model.predict(x3)

    l_temp.loc[-1]=y_pred1[0]

    predict_name_BPS_Without_Classes = l_temp.loc[-1].idxmax()
    return predict_name_BPS_Without_Classes

def testingWithFingerprint(BPS_list):
    #checking with BPS model        
    model_path=r"E:\ads\models\DF BPS\DF_769000000000000.h5"   
    model = load_model(model_path)
    #l_temp=pd.read_pickle(r"E:\8-ModelsIntegrationCode\Code\DFModel\Train_FP1.pkl")
    import pickle5 as pickle
    data = ""
    with open(r"E:\ads\models\DF BPS\Train_FP1.pkl", "rb") as fh:
      data = pickle.load(fh)
    l_temp=(data)
    array = BPS_list[0:21]
    v=769000000000000#change this
    x1=np.vectorize(norm)(array,v)
    labels = np.asarray(l_temp, dtype = np.int8)
    x3 = x1.reshape(1,21,1)
    y_pred1 = model.predict(x3)
    l_temp.loc[-1]=y_pred1[0]
    predict_name = l_temp.loc[-1].idxmax()
    return predict_name
    
def preditWithFingerprint(BPS_list):
    # data to be written row-wise in csv fil
    data = [BPS_list]
      
    # opening the csv file in 'w+' mode
    file = open(r"E:\8-ModelsIntegrationCode\Results\test_BPS test.csv", 'w', newline ='')
      
    # writing the data into the file
    with file:    
        write = csv.writer(file)
        write.writerows(data) 
    file.close()
        
    dataorig =  pd.read_csv(r"E:\8-ModelsIntegrationCode\Results\test_BPS test.csv",header=None)
    data = dataorig.copy()
    data = data.iloc[:,:-1]
    labels = dataorig.iloc[:,-1].values
    # difFrame=pd.DataFrame()
    
    
    periodDataFrame= pd.DataFrame()
    periodMax = 5
    dataThreshold = 5000
    
    # print("DATA ",data[][0]) # data [column][row]
    # print("NO of rows",len(data.index))
    # print("NO of COL",len(data.columns))
    
    
    for i in range(len(data.index)):
        timeP = 0
        dataP = 0
        bpP = []
    
        for j in range(len(data.columns)):
            if j-timeP >= periodMax:
                timeP=j
                bpP.append(dataP)
                dataP = 0
            if data[j][i] < dataThreshold:
                continue
            dataP += data[j][i]
        bpP = pd.Series(bpP)
        periodDataFrame=periodDataFrame.append(bpP,ignore_index=True)
        
    data = periodDataFrame.copy()
    data = data.iloc[:,:-1]
    difFrame=pd.DataFrame()
    
    data.replace(0,1,inplace=True)
    for i in range (1,len(data.columns)):
        #print(i)
        #dif = (data.iloc[:,i]-data.iloc[:,i-1])                #FP1
        # dif = (data.iloc[:,i]-data.iloc[:,i-1])/data.iloc[:,i-1] #FP2
        dif = (data.iloc[:,i]-data.iloc[:,i-1])**2                #FP3 in works
        difFrame.insert(i-1,str(i),dif)
    
    # for i in range (1,22):
    #     data.insert((2+(i-1)*2),str(i)+"-"+str(i-1),difFrame.iloc[:,i-1])
    difFrame.insert(len(difFrame.columns), None, labels)
    #difFrame.to_csv(r"E:\8-ModelsIntegrationCode\Results\Generated_Fingerprint_"+currentdate+".csv",mode='a',encoding='utf-8',index=False,header=False)
    
    #print(difFrame.iloc[0])
    predict_name = testingWithFingerprint(difFrame.iloc[0])
    return predict_name

def remove_ether_header(packet):
    if Ether in packet:
        return packet[Ether].payload

    return packet

def mask_ip(packet):
    if IP in packet:
        packet[IP].src = '0.0.0.0'
        packet[IP].dst = '0.0.0.0'

    return packet

def pad_udp(packet):
    if UDP in packet:
        # get layers after udp
        layer_after = packet[UDP].payload.copy()

        # build a padding layer
        pad = Padding()
        pad.load = '\x00' * 12

        layer_before = packet.copy()
        layer_before[UDP].remove_payload()
        packet = layer_before / pad / layer_after

        return packet

    return packet
    
def should_omit_packet(packet):
    # SYN, ACK or FIN flags set to 1 and no payload
    if TCP in packet and (packet.flags & 0x13):
        # not payload or contains only padding
        layers = packet[TCP].payload.layers()
        if not layers or (Padding in layers and len(layers) == 1):
            return True

    # DNS segment
    if DNS in packet:
        return True

    return False

def transform_packet(packet):
    # if should_omit_packet(packet):
    #     return None

    packet = remove_ether_header(packet)
    packet = pad_udp(packet)
    packet = mask_ip(packet)

    return packet

def isValidSource(packet,moIP):
    if IP in packet:
        if (packet[IP].src == moIP ):
             return True
    return False

def mostOccuredIPFinder(file):
    ipsSet =set((p[IP].src, p[IP].dst,p[IP].proto) for p in PcapReader(file) if IP in p)
    mostOccuredIp=""
    if(len(ipsSet)<=2):
        ipss=""
        for i in ipsSet:
            ipss=i
            break
        mostOccuredIp = ipss[0]
        if mostOccuredIp == "172.16.100.7":
            mostOccuredIp = ipss[1]
    else:
        uniqueB=[]
        for i in ipsSet:
            uniqueB.append(i[1])
            
        from collections import Counter
        occurence_count = Counter(uniqueB)
        mostOccuredIp = occurence_count.most_common(1)[0][0]
    return mostOccuredIp

def testingWithFlowpic(filename):
    
    out_path = r"E:\8-ModelsIntegrationCode\FlowPics\\"
    #path_of_csv = r"E:\ads\models integration code\VPN.csv"
    
    
    path_to_file = filename
    ImgName = path_to_file.split("\\")[-1].split(".")[0]
    
    Allpackets=rdpcap(path_to_file)
    moIP = mostOccuredIPFinder(path_to_file)
    print(ImgName)
    
    packet_info = pd.DataFrame()
    packet_length = []
    packet_time = []
    
    for p in Allpackets:
        # check = isValidSource(packet,moIP)
        # if check:
        packet=transform_packet(p)
        if packet is not None:
           packet_length.append(len(packet))
           packet_time.append(p.time)
    
    packet_info = packet_info.append(pd.DataFrame({'Packet_Length':packet_length,'Packet_Arrival':packet_time})) 
    
    packet_info['Packet_Arrival'] = (packet_info['Packet_Arrival']-min(packet_info['Packet_Arrival']))/(max(packet_info['Packet_Arrival'])-min(packet_info['Packet_Arrival']))
    
    packet_info['Packet_Arrival'] = packet_info['Packet_Arrival'] * 120 
    fig=plt.gcf()
    pltt.close()
    pltt.cla()
    pltt.clf()
    pltt.ioff()
    #plt.figure(figsize=(6,4))
    pltt.autoscale(False)
    px = 1/pltt.rcParams['figure.dpi']  # pixel in inches
    pltt.subplots(figsize=(3600*px, 2400*px))
   
    #pd.set_option("display.max_rows", None, "display.max_columns", None)
    print(packet_info)
    pltt.ylim(ymax = 1500, ymin=0)
    #plt.xlim(xmax = 1400, xmin=0)
    pltt.scatter(packet_info['Packet_Arrival'], packet_info['Packet_Length'], color= "black", marker= "s", s=30)
    bottom, top = plt.ylim()
    print(bottom, top)
    filename = out_path + ImgName +'.png'
    # filenameT = out_pathT+traffic_label+'_'+str(count)+'.png'
    
    pltt.savefig(filename,dpi = 60)
    # plt.savefig(filenameT,dpi=600)
    
    print("saved image filename is ",filename)
    # plt.savefig(filenameT,dpi=600)

    #sending data for plot generation on front page
    plt.title('Flow pic')
    plt.ylabel('Packet size')
    fig=plt.gcf()
    buf = io.BytesIO()
    fig.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri10 = urllib.parse.quote(string)
    
    pltt.close()

    model = load_model(r"E:\ads\models\Flowpic\TrafficPatternPlotAutoModel.h5")
    # load and prepare the image
    img=load_image(filename)
    #predict images
    model.predict(img)
    linksList = ["link1","link111","link112","link113","link114","link115","link116","link117","link118","link119","link120","link121","link122","link123","link124","link125","link126","link128","link129","link2","link3","link31","link32","link33","link34","link35","link36","link38","link39","link40","link41","link85","link86","link87","link88","link89","link90","link91","link92","link93","link94","link95","link96"]
    predict_name = linksList[numpy.argmax(model.predict(img))]
    print(predict_name)
    return predict_name,uri10
    
def load_image(filename):
    # load the image
    img = load_img(filename)
    print(img.size)
    # convert to array
    img = img_to_array(img)
    # reshape into a single sample with 3 channels
    img = img.reshape( 1,360, 240, 3)# center pixel data
    img = img.astype('float32')
    img = img - [123.68, 116.779, 103.939]
    return img

def generate_PAT(path_to_PCAP,dirName):
   
    out_path = r"E:\ads\models\DF PAT\PAT-iteration.csv"
    path_to_file = path_to_PCAP
   
    Allpackets=rdpcap(path_to_file)
   # moIP = mostOccuredIPFinder(path_to_file)
   
    packet_info = pd.DataFrame()
    packet_length = []
    packet_time = []
    
    for p in Allpackets:
        # check = isValidSource(packet,moIP)
        # if check:
        packet=transform_packet(p)
        if packet is not None:
           packet_length.append(len(packet))
           # print(p.time)
           # print(len(packet))
           # time.sleep(2)
           packet_time.append(p.time)

    packet_info = packet_info.append(pd.DataFrame({'Packet_Length':packet_length,'Packet_Arrival':packet_time})) 
    
    packet_info['Packet_Arrival'] = (packet_info['Packet_Arrival']-min(packet_info['Packet_Arrival']))/(max(packet_info['Packet_Arrival'])-min(packet_info['Packet_Arrival']))
    #print( packet_info['Packet_Arrival'])
    
    packet_info['Packet_Arrival'] = packet_info['Packet_Arrival'] * 120
    seconds = [i for i in range(120)]
    sample_PAT = []
    for i in seconds:
        # df = packet_info.loc((packet_info['Packet_Arrival']>=i) & (packet_info['Packet_Arrival']<i+1) )
        df_second = packet_info[  (packet_info['Packet_Arrival']>=i) & (packet_info['Packet_Arrival']<i+1) ]
        aggr = df_second['Packet_Length'].sum()
        sample_PAT.append(aggr)
    
    sample_PAT.append(str(dirName))
    #sample_PAT.append(str(FileName))
    with open (out_path,'a',newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(sample_PAT)
    
    return sample_PAT

def preditWithPATFingerprint(BPS_list,name):
    # data to be written row-wise in csv fil
    data = [BPS_list]
      
    # opening the csv file in 'w+' mode
    file = open(r"E:\ads\models\DF PAT\test_PAT test.csv", 'w', newline ='')
      
    # writing the data into the file
    with file:    
        write = csv.writer(file)
        write.writerows(data) 
    file.close()
        
    dataorig =  pd.read_csv(r"E:\ads\models\DF PAT\test_PAT test.csv",header=None)
    data = dataorig.copy()
    data = data.iloc[:,:-1]
    labels = dataorig.iloc[:,-1].values
    # difFrame=pd.DataFrame()
    
    
    periodDataFrame= pd.DataFrame()
    periodMax = 5
    dataThreshold = 5000
    
    # print("DATA ",data[][0]) # data [column][row]
    # print("NO of rows",len(data.index))
    # print("NO of COL",len(data.columns))
    
    
    for i in range(len(data.index)):
        timeP = 0
        dataP = 0
        bpP = []
    
        for j in range(len(data.columns)):
            if j-timeP >= periodMax:
                timeP=j
                bpP.append(dataP)
                dataP = 0
            if data[j][i] < dataThreshold:
                continue
            dataP += data[j][i]
        bpP = pd.Series(bpP)
        periodDataFrame=periodDataFrame.append(bpP,ignore_index=True)
        
    data = periodDataFrame.copy()
    data = data.iloc[:,:-1]
    difFrame=pd.DataFrame()
    
    data.replace(0,1,inplace=True)
    for i in range (1,len(data.columns)):
        dif = abs((data.iloc[:,i]-data.iloc[:,i-1]))
        #print(i)
        #dif = (data.iloc[:,i]-data.iloc[:,i-1])                #FP1
        # dif = (data.iloc[:,i]-data.iloc[:,i-1])/data.iloc[:,i-1] #FP2
        #dif = (data.iloc[:,i]-data.iloc[:,i-1])**2                #FP3 in works
        difFrame.insert(i-1,str(i),dif)
    
    # for i in range (1,22):
    #     data.insert((2+(i-1)*2),str(i)+"-"+str(i-1),difFrame.iloc[:,i-1])
    difFrame.insert(len(difFrame.columns), None, labels)
    #difFrame.to_csv(r"E:\ads\models\DF PAT\Fingerprint_PAT_"+currentdate+".csv",mode='a',encoding='utf-8',index=False,header=False)
    
    #print(difFrame.iloc[0])
    return testingWithFingerprintPAT(difFrame.iloc[0],name)
    

def testingWithFingerprintPAT(PAT_list,video_name):
    #checking with BPS model        
    model_path=r"E:\ads\models\DF PAT\ADF_PAT_35946156.h5"    
    model = load_model(model_path)
    with open(r"E:\ads\models\BPS model\NonVPN_04-01-2022-10-46_9830494.pkl", "rb") as fh:
      data = pickle.load(fh)
    l_temp=(data)
    array = PAT_list[0:21]
# =============================================================================
#     x = []
#     df =  pd.DataFrame (array, columns = ['column_name'])
#     df['column_name'] = df['column_name'].astype(int)
#     #name = str(df[i,121:].values.tolist())
#     x = df['column_name'] #
# =============================================================================
     
    v= int(model_path.split("_")[-1].split(".")[0]) #change this
    #v=int(model_path.split("_")[-1].split(".")[0])
    
    
    
    x1=np.vectorize(norm)(array,v)
    
    labels = np.asarray(l_temp, dtype = np.int8)
    x3 = x1.reshape(1,21,1)
    y_pred1 = model.predict(x3)
    
    l_temp.loc[-1]=y_pred1[0]
    
    predict_name = l_temp.loc[-1].idxmax()
    print("Video name was ",video_name,". The predicted link is with PAT is : ",predict_name)
    
    return predict_name

def remotePcTesting(request):
    #result = request.GET["cars"].split(",")[1]
    #linkNumberr = request.GET["cars"].split(",")[0]
    #linkNumber = linkNumberr.replace(" ","")
    linkNumber = "remotePc"
    linkNumberr = "remotePc"
    result = "remotePc"
    #data = pd.read_csv("links.csv")
    i=0
    BPS_list=[]
    while (i < 1):
        #print(str(data['id'][i]) + ": " + str(data['Links'][i]))
        filename = linkNumber
        #urlF = str(result)
        amount = 1
        #link100_url = urlF
        link100_duration = 10
        filename = harvest_video_remote(amount,filename,link100_duration)
        print(filename)
        i+=1
    ips=[]
    ipsSet =set((p[IP].src, p[IP].dst,p[IP].proto) for p in PcapReader(filename) if IP in p)
    mostOccuredIp=""
    
    if(len(ipsSet)<=2):
        
        for i in ipsSet:
            ipss=i
            break
        mostOccuredIp = ipss[0]
        if mostOccuredIp == "172.16.100.7":
            mostOccuredIp = ipss[1]
    else:
        uniqueB=[]
        for i in ipsSet:
            print(i)
            uniqueB.append(i[1])
            
        from collections import Counter
        occurence_count = Counter(uniqueB)
        mostOccuredIp = occurence_count.most_common(1)[0][0]
        
    print("ip is", mostOccuredIp)
    with open("E:\\ads\\toolV1.2\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        file = filename
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
        BPS_list=bytes_per_second['frame.len'][0:120]
        
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 120:
            print("len is less")
            diff = 120- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        BPS_list.append(linkNumberr)
        writer.writerow(BPS_list)

    plt.cla()
    plt.close()
    plt.clf()
    #bytes per second 
  
    x = []
    y = []
    array = []
    with open('E:\\ads\\toolV1.2\\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv','r') as csvfile:
        plots = csv.reader(csvfile, delimiter = ',')
        print(plots) 
        for col in plots:
            col = col[0:-1]
            array = col
            for i in range(len(col)):
                print(col[i])
                x.append(i)
                y.append(int(col[i]))
    plt.rcParams["figure.figsize"] = (7,2)
    plt.rcParams['figure.dpi'] = 600
    plt.bar(x, y, color = 'black', width = 0.72 )
    plt.xlabel('Time(s)')
    plt.ylabel('Bytes per second')
    plt.title('Bytes per second')
    import urllib,base64
    plt.plot()
    fig=plt.gcf()
    buf = io.BytesIO()
    fig.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri = urllib.parse.quote(string)
    df =  pd.DataFrame (array, columns = ['column_name'])
    df['column_name'] = df['column_name'].astype(int)
    mean = df['column_name'].mean()
    std = df['column_name'].std()
    firstQuartile  =  df.column_name.quantile([0.25]).to_string(index=False)
    median = df.column_name.quantile([0.50]).to_string(index=False)
    secondQuartile =  df.column_name.quantile([0.75]).to_string(index=False)
    plt.close()

    #bytes per peak
    xx = []
    yy = []

    sum=0
    with open('E:\\ads\\toolV1.2\\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv','r') as csvfile:
        plots = csv.reader(csvfile, delimiter = ',')
        print(plots)
        for col in plots:
            print(col)
            col = col[0:-1]
            
            for i in range(len(col)):
                
                if i<len(col)-1:   
                    if int(col[i+1])!= 0 :
                        sum=sum+int(col[i])
                    else:
                        sum=sum+int(col[i])
                        if sum!=0:
                            yy.append(sum)
                            
                            sum=0
                else:
                    sum=sum+int(col[i])
                    yy.append(sum)
    xx=range(1,len(yy)+1)                
    plt.rcParams["figure.figsize"] = (7,2)
    plt.rcParams['figure.dpi'] = 600
    plt.bar(xx,yy, color = 'black', width = 0.72 )
    plt.xlabel('Time(s)')
    plt.ylabel('Bytes per Peak')
    plt.title("Bytes per Peak")
    plt.plot()
    figgggggg=plt.gcf()
    buf = io.BytesIO()
    figgggggg.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri5 = urllib.parse.quote(string)
    BPS_list.clear()
    plt.close()

    
    #packets per second 
    with open(r"E:\\ads\\toolV1.2\\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
           
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        file = filename
        newBPS_list = []
        newBPS_list2= []
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        packet_per_second=source_address.resample("s", on='frame.time_epoch').count()
        BPS_list=packet_per_second['frame.len'][0:120]
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 120:
            print("len is less")
            diff = 120- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        plt.bar(range(len(BPS_list)),BPS_list,color = 'black', width = 0.72)
        plt.rcParams["figure.figsize"] = (7,2)
        plt.rcParams['figure.dpi'] = 600
        plt.title('Packets per second')
        plt.xlabel('Time(s)')
        plt.ylabel('Packet per second')
        plt.plot()
        figg=plt.gcf()
        buf = io.BytesIO()
        figg.savefig(buf,format='png')
        buf.seek(0)
        string = base64.b64encode(buf.read())
        uri1 = urllib.parse.quote(string)
        BPS_list.clear()
        plt.close()
    #instantaneous graph
    with open(r"E:\\ads\\toolV1.2\\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        file = filename
        newBPS_list = []
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
            
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        bytes_per_second=source_address.resample("100ms", on='frame.time_epoch').sum()
    
        BPS_list=bytes_per_second['frame.len'][0:1200]
        
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 1200:
            print("len is less")
            diff = 1200- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        for data in BPS_list:
            temp = (data/1024)
            newBPS_list.append(temp)
        plt.rcParams["figure.figsize"] = (7,2)
        plt.rcParams['figure.dpi'] = 600
        
        plt.plot(newBPS_list)

        plt.title('Bytes per 100ms')
        plt.xlabel('Time(ms)')
        plt.ylabel('Instantaneous data (KB)')
        plt.plot()
        figgg=plt.gcf()
        buf = io.BytesIO()
        figgg.savefig(buf,format='png')
        buf.seek(0)
        string = base64.b64encode(buf.read())
        uri2 = urllib.parse.quote(string)
        BPS_list.clear()
        plt.close()


    #short on and off cycle
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        newBPS_list = []
        newBPS_list2= []
        file =  filename
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
        BPS_list=bytes_per_second['frame.len'][0:120]
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 120:
            print("len is less")
            diff = 120- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        for data in BPS_list:
            temp = (data/1024)/1024
            newBPS_list.append(temp)
        cdf = np.cumsum(newBPS_list)
    plt.plot(cdf)
    plt.title('Data downloaded')
    plt.xlabel('Time(s)')
    plt.ylabel('Download Amount (MB)')
    plt.rcParams["figure.figsize"] = (7,2)
    plt.rcParams['figure.dpi'] = 600
    figggg=plt.gcf()
    buf = io.BytesIO()
    figggg.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri3 = urllib.parse.quote(string)
    BPS_list.clear()
    plt.close()
    BPS_list.clear()

    #normalized
             
      
    fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
    
    newBPS_list = []
    newBPS_list2= []
    file =  filename
    temp=read_pcap(file, fields, timeseries=True, strict=True)
    temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
    
    source_address=temp[temp["ip.dst"] == mostOccuredIp]
    bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()

    BPS_list=bytes_per_second['frame.len'][0:120]

    BPS_list = list(map(_replaceitem, BPS_list))
    lenBPS = len(BPS_list)
    if lenBPS < 120:
        print("len is less")
        diff = 120- lenBPS
        for d in range(diff):
            BPS_list.append(0)
    for data in BPS_list:
        temp = (data/1024)/1024
        newBPS_list.append(temp)
    normalized = (cdf-min(cdf))/(max(cdf)-min(cdf))
    plt.plot(normalized)
    plt.title('Cumulative downloaded data')
    plt.xlabel('Time(s)')
    plt.ylabel('CDF')
    plt.rcParams["figure.figsize"] = (7,2)
    plt.rcParams['figure.dpi'] = 600
    figgggg=plt.gcf()
    buf = io.BytesIO()
    figgggg.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri4 = urllib.parse.quote(string)
    BPS_list.clear()
    plt.close()
    BPS_list.clear()
    
    #model predication
    #------------------- df  = list of BPS -----------------
    BPS_list=[]
    with open("E:\\ads\\toolV1.2\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        file = filename
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
        BPS_list=bytes_per_second['frame.len'][0:120]
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 120:
            print("len is less")
            diff = 120- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        BPS_list.append(linkNumberr)
        writer.writerow(BPS_list)
    
    array = BPS_list[0:120]
    plt.cla()
    plt.close()
    plt.clf()

    #dict of links
    linksDict = {"link1":"Learn Object Oriented Programming in 10 minutes (Java)","link111":"Arslan Ash vs Knee - EVO 2019 Grand Finals - Tekken 7","link112":"How To Make Marble Cake At Home in Urdu I Marble Cake Recipe I No Oven Cake Recipe I Marble Tea Cake","link113":"Mozzarella Cheese Recipe By ijaz Ansari | How To Make Mozzarella Cheese At Home | No Rennet |","link114":"Extra Crispy Fried Chicken Recipe By Food Fusion (Ramzan Special)","link115":"10 Most Expensive Things Dwayne The Rock Johnson Owns - MET Ep 14","link116":"Shahid Afridi Home Tour | Exclusive Video","link117":"Ek Sharabi Jo Sharab Se Roza Iftar Krta Tha | Latest Ramadan Bayan by Maulana Tariq Jameel 2017","link118":"Daniel Bryan & Roman Reigns vs. Seth Rollins Big Show Kane & J&J Security: Raw February 9 2015","link119":"Spintop Snipers | Amazing Top Trick Shots!","link120":"Random Acts of Kindness - Faith In Humanity Restored #3","link121":"Sony - World's First Smartphone To Do This","link122":"AVENGERS ENDGAME Becoming Fat Thor Behind the Scenes Bonus Clip (2019) Chris Hemsworth Move HD","link123":"ScaleTrains BNSF HO Scale Dash 9 C44-9W Unboxing","link124":"Xiaomi Mi Mix Alpha Impressions: The Wraparound Display!","link125":"Shan-e-Iftar - Shan E Dastarkhwan [Chicken Parmesan] - 23rd April 2021 - Chef Farah","link126":"Latest Trouser Design 2021 | Capri Design 2021 | Plazo Pant Design","link128":"VW Amarok Tackling Gunshot Creek Sept 2015","link129":"Eau De Bean | Mr Bean Cartoon Season 3 | NEW FULL EPISODE | Season 3 Episode 12 | Mr Bean Official","link2":"Why You Shouldn’t Learn Python In 2021","link3":"10 LATEST TECHNOLOGY INVENTIONS ▶ Smart Vehicle You Must See","link31":"Can My Water Cooled Raspberry Pi Cluster Beat My MacBook?","link32":"LIFE IN RAMZAN! | COMEDY VIDEO","link33":"Russell Shakib & Malan Join in | Zero Tolerance required for PSL Protocols","link34":"TensorFlow.js Quick Start","link35":"you need to learn Virtual Machines RIGHT NOW!! (Kali Linux VM Ubuntu Windows)","link36":"Coding Interview | Software Engineer @ Bloomberg (Part 1)","link38":"Amazing Brathwaite 100! | West Indies v New Zealand - Match Highlights | ICC Cricket World Cup 2019","link39":"Ferocious Dinosaur Moments | Top 5 | BBC Earth","link40":"10 Latest NEW TECH GADGETS AND INVENTIONS 2020 | Available On Amazon | You Can Buy in ONLINE STORE","link41":"Ranking push of my team's OP Play video | Many Hackers | PUBG MOBILE","link85":"AIRPLANE Bean | Bean Movie | Funny Clips | Mr Bean Official","link86":"Mini LED cube with 54 pixel WiFi & gyroscope | SMT hotplate soldering | Pikocube v2.0","link87":"ASMR Video | Build Modern Glass Elevator For Underground And Rooftop Infinity Swimming Pool","link88":"NEW BEST LANDING IN MILITARY BASE","link89":"Random Facts Around The World | Part 57 | Urdu / Hindi","link90":"How THANOS Knew TONY In Avengers: Infinity War? | Super Questions Ep. 5 | Super Access","link91":"Data Center NETWORKS (what do they look like??) // FREE CCNA // EP 7","link92":"New Ghar Saman Shift Karna Shuru Kar diya","link93":"2v4 CLUTCH FOR THE WWCD • PMPL FINALS • 2 MAN CHICKEN DINNER •","link94":"MAKING A SNEAKER ROOM IN MY NEW HOUSE!","link95":"5 Richest Kids Of Pakistan | TOP X TV","link96":"Levels of Ultra Instinct (1% - 50% - 100%)"}

    # ensemble list
    ensembleList = []

    #BPS model
    predict_name = BPSModel(array)
    ensembleList.append(predict_name)
    print("predicted by BPS is ", predict_name)
    predict_name = linksDict[predict_name]

    #detect BPS - Classes (VPN vs NonVPN)
    #predict_name_BPS_Classes = BPSClassesVPNvsNonVPN(array)
    #print("predicted by BPS with classes is ", predict_name_BPS_Classes)
    
    #BPS - Without Classes (VPN vs NonVPN)
    predict_name_BPS_Without_Classes = BPSWithoutClassesVPNvsNonVPN(array)
    print("predicted by BPS without classes is ", predict_name_BPS_Without_Classes)
    
    #DF model 
    predict_name_DF = testingWithFingerprint(array)
    ensembleList.append(predict_name_DF)
    print("predicted by df is ", predict_name_DF)
    predict_name_DF = linksDict[predict_name_DF]
    
    #PAT model
    PATBpsList = generate_PAT(filename,linkNumberr)
    predict_name_PAT = preditWithPATFingerprint(PATBpsList, linkNumberr)
    ensembleList.append(predict_name_PAT)
    print("predicted by PAT is ", predict_name_PAT)
    predict_name_PAT = linksDict[predict_name_PAT]

    #flowpic
    predict_name_FP,uriFP = testingWithFlowpic(filename)
    print("predicted by fp is ", predict_name_FP)
    predict_name_FP = linksDict[predict_name_FP]

    #ensemble
    predict_name_ensemble = ensemble(ensembleList)
    print(ensembleList)
    print("predicted by ensemble is ", predict_name_ensemble)
    if predict_name_ensemble != "Ensemble failed":
        predict_name_ensemble = linksDict[predict_name_ensemble]
    
    
    return render(request,"page2.html",{'cars':result,'data':uri,"mean":mean,"std":std,"qur1":firstQuartile,"median":median,"qur2":secondQuartile,"packetsPerSecond":uri1,"Instantaneous":uri2,"shortOnOffCycle":uri3,"normalized":uri4,"bytesPerPeak":uri5,"flowPicImg":uriFP,"linkNumber":linkNumberr,"predictedName":predict_name,"bpsWithoutClasses":predict_name_BPS_Without_Classes,"DF":predict_name_DF,"FP":predict_name_FP,"PAT":predict_name_PAT,"ensemble":predict_name_ensemble})

def clickOnAd(driver):
    try:
        res = driver.find_element_by_xpath("//*[contains(text(),'Skip Ad')]").click()        
    except:
        print("didn't find ad video ad insertion")

def downloadVideo(video_quality,video_name, url, duration_of_the_video):
    """
        The function receives:
        - video _quality: which indicates what quality the robot will download: 360P,480P,720P or AUTO mode.
        - video_name: we used it to create a new folder for this video. if the folder exists we only save the PCAP in to this specific folder.
        - url: video url
        - duration_of_the_video: when to stop recording the video. In my testing the duration of the video was enough (even with ads). If it is change increase it.
        
    """
    t_time = time.strftime("%H_%M_%S")
    funcInFile = "Test"
    #create pcap folder
    root_path = "E:\\ads\\toolv1.2\\mysite\\ModifiedPcapsselectedpcap\\"
    #root_path = "testpcap\\"
    if not os.path.exists(root_path):
        os.makedirs(root_path)
    #create video folder    
    video_path = root_path + video_name +"\\"
    if not os.path.exists(video_path):
        os.makedirs(video_path)
    
    #create quality folder
    quality_path =  video_path +  funcInFile + "\\"
    if not os.path.exists(quality_path):
        os.makedirs(quality_path)
    #folder = "C:\\Users\\user\\Desktop\\ranTests\\pcap\\" + video_name + "\\"+ video_quality
    filename = quality_path + video_name + "_"  + funcInFile + t_time + ".pcap"
    tsharkOut  = open(filename, "wb")
    tsharkCall = ["C:\\Program Files\\Wireshark\\tshark.exe","-F", "pcap", "-f", "port 443", "-i", "Wi-Fi 2", "-w", filename]#8-fixed line 3 wifi in my pc
    tsharkProc = ""
    chrome_options = webdriver.ChromeOptions()


    #this one worked
    chrome_options.binary_location ="C:\Program Files\Google\Chrome\Application\chrome.exe"
    #chrome_options.add_extension('adblockpluschrome-1.8.10.1352.crx') #note I used this one in the past. I had problems that the browser didn't close itself when I used adblock.
    chrome_options.add_extension('adblock.crx') #note I used this one in the past. I had problems that the browser didn't close itself when I used adblock.
    

    #driver = webdriver.Chrome(executable_path='C:\Python27\Scripts\chromedriver.exe',chrome_options=chrome_options)
    driver = webdriver.Chrome(executable_path='chromedriver.exe',options=chrome_options)
    
   
    
    #driver = webdriver.Chrome(chrome_options=chrome_options)//ran
    #driver = webdriver.Chrome(executable_path = 'C:\Python27\Scripts\chromedriver.exe', chrome_options = 'C:\Users\user\Desktop\ranTests\adblockpluschrome-1.8.10.1352.crx')
    wait = WebDriverWait(driver, 100)
    driver.get(url)
    
   
    #Note: this option is disables since I am working with the auto mode. for fixed quality you will need to use this.!
    print('Note: for fixed qualities please enable this feature in the code')
    #wait.until(EC.element_to_be_clickable((By.XPATH,"//button[@aria-label='Settings']")))
   # driver.find_element_by_class_name("ytp-menuitem-label").click()
    #time.sleep(1)
    #//worked
    #click = driver.find_element_by_id('settings_button').click()
    #
    if video_quality == "360P":
        wait.until(EC.element_to_be_clickable((By.XPATH,"//*[contains(text(),'360p')]")))
        time.sleep(0.3)
        driver.find_element_by_xpath("//*[contains(text(),'360p')]").click()
        time.sleep(15)
        clickOnAd(driver)
                  
    if video_quality == "480P":
        wait.until(EC.element_to_be_clickable((By.XPATH,"//*[contains(text(),'480p')]")))
        time.sleep(0.3)
        driver.find_element_by_xpath("//*[contains(text(),'480p')]").click()
        time.sleep(15)
        clickOnAd(driver)
    if video_quality == "720P":
        wait.until(EC.element_to_be_clickable((By.XPATH,"//*[contains(text(),'720p')]")))
        time.sleep(0.5)
        driver.find_element_by_xpath("//*[contains(text(),'720p')]").click()
        time.sleep(15)
        clickOnAd(driver)
    if video_quality == "1080P":
        wait.until(EC.element_to_be_clickable((By.XPATH,"//*[contains(text(),'1080p HD')]")))
        time.sleep(0.5)
        driver.find_element_by_xpath("//*[contains(text(),'1080p')]").click()
        time.sleep(15)
        clickOnAd(driver)
    if video_quality == "Auto":
        time.sleep(2)
        #driver.find_element_by_tag_name('body').send_keys(Keys.CONTROL + Keys.TAB)
        clickOnAd(driver)
        tsharkProc = subprocess.Popen(tsharkCall, stdout=tsharkOut, executable="C:\\Program Files\\Wireshark\\tshark.exe")
        wait.until(EC.element_to_be_clickable((By.XPATH, "//button[@aria-label='Play']"))).click()
        print('switching tabs')
        driver.switch_to.window(driver.window_handles[0])
        #time.sleep(15)
    
    time.sleep(duration_of_the_video)
    driver.quit()
    tsharkProc.kill()
    return filename

def harvest_video(amount,name,url,duration):
    filename_=""
    for x in range(0, amount):
        # print('Automatic quality')
        print('run number:', x)
        filename_ = downloadVideo("Auto",name,url,duration)
        #print('Note: for fixed quality please enable this lines in the code')
        #print('Capturing  360P')
        #downloadVideo("360P",name,url,duration)
        #print('Capturing  480P')
        #downloadVideo("480P",name,url,duration)
        #print('Capturing  720P')
        #downloadVideo("720P",name,url,duration)
        #print('Capturing  1080P')
        #downloadVideo("1080P",name,url,duration)
    return filename_

#remoteTesting

def downloadVideoRemote(video_quality,video_name, duration_of_the_video):
    """
        The function receives:
        - video _quality: which indicates what quality the robot will download: 360P,480P,720P or AUTO mode.
        - video_name: we used it to create a new folder for this video. if the folder exists we only save the PCAP in to this specific folder.
        - url: video url
        - duration_of_the_video: when to stop recording the video. In my testing the duration of the video was enough (even with ads). If it is change increase it.
        
    """
    t_time = time.strftime("%H_%M_%S")
    funcInFile = "Test"
    #create pcap folder
    root_path = "E:\\ads\\toolv1.2\\mysite\\ModifiedPcapsselectedpcap\\"
    #root_path = "testpcap\\"
    if not os.path.exists(root_path):
        os.makedirs(root_path)
    #create video folder    
    video_path = root_path + video_name +"\\"
    if not os.path.exists(video_path):
        os.makedirs(video_path)
    
    #create quality folder
    quality_path =  video_path +  funcInFile + "\\"
    if not os.path.exists(quality_path):
        os.makedirs(quality_path)
    #folder = "C:\\Users\\user\\Desktop\\ranTests\\pcap\\" + video_name + "\\"+ video_quality #Local Area Connection* 12
    filename = quality_path + video_name + "_"  + funcInFile + t_time + ".pcap"
    tsharkOut  = open(filename, "wb")
    tsharkCall = ["C:\\Program Files\\Wireshark\\tshark.exe","-F", "pcap", "-f", "port 443", "-i", "Wi-Fi 2", "-w", filename]#8-fixed line 3 wifi in my pc
    tsharkProc = ""
    
   
    
   
    print("starting capturing remote pc traffic")
    tsharkProc = subprocess.Popen(tsharkCall, stdout=tsharkOut, executable="C:\\Program Files\\Wireshark\\tshark.exe")
    time.sleep(duration_of_the_video)
    tsharkProc.kill()
    print("now detecting, done capturing remote pc traffic")
    return filename

def harvest_video_remote(amount,name,duration):
    filename_=""
    for x in range(0, amount):
        # print('Automatic quality')
        print('run number:', x)
        filename_ = downloadVideoRemote("Auto",name,duration)
        #print('Note: for fixed quality please enable this lines in the code')
        #print('Capturing  360P')
        #downloadVideo("360P",name,url,duration)
        #print('Capturing  480P')
        #downloadVideo("480P",name,url,duration)
        #print('Capturing  720P')
        #downloadVideo("720P",name,url,duration)
        #print('Capturing  1080P')
        #downloadVideo("1080P",name,url,duration)
    return filename_


def read_pcap(filename, fields=[], display_filter="", timeseries=False, strict=False):
    if timeseries:
        fields = ["frame.time_epoch"] + fields
    fieldspec = " ".join("-e %s" % f for f in fields)
    display_filters = fields if strict else []
    if display_filter:
        display_filters.append(display_filter)
    filterspec = "-R '%s'" % " and ".join(f for f in display_filters)
    options = "-r %s -2 -T fields -Eheader=y" % filename
    cmd = "tshark %s %s" % (options, fieldspec)
    proc = subprocess.Popen(cmd, shell = True,stdout=subprocess.PIPE)
    df = pd.read_table(proc.stdout)
    return df

def _replaceitem(x):
    if x < 4:
        return 0
    
    else:
        return x

#ensemble 
def ensemble(List):
    counter = 0
    num = List[0]
    for i in List:
        curr_frequency = List.count(i)
        if(curr_frequency> counter):
            counter = curr_frequency
            num = i
    print(counter)
    if counter >= 2:
        return num 
    else:
        return "Ensemble failed"

from django.shortcuts import render, HttpResponse


def upload(request):
    if request.method == "POST":
        file_name = request.FILES["myFile"].file.name
        #extract ip from pcap
        ips=[]
        ipsSet =set((p[IP].src, p[IP].dst,p[IP].proto) for p in PcapReader(file_name) if IP in p)
        mostOccuredIp=""
        if(len(ipsSet)<=2):
            for i in ipsSet:
                ipss=i
                break
            mostOccuredIp = ipss[0]
            if mostOccuredIp == "172.16.100.7":
                mostOccuredIp = ipss[1]
        else:
            uniqueB=[]
            for i in ipsSet:
                print(i)
                uniqueB.append(i[1])
                
            from collections import Counter
            occurence_count = Counter(uniqueB)
            mostOccuredIp = occurence_count.most_common(1)[0][0]
        print("ip is", mostOccuredIp)
        with open("E:\\ads\\toolV1.2\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv", "w", newline="") as csv_file:
            writer = csv.writer(csv_file)
            
            fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
            
            file = file_name
            temp=read_pcap(file, fields, timeseries=True, strict=True)
            temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
            source_address=temp[temp["ip.dst"] == mostOccuredIp]
            bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
            BPS_list=bytes_per_second['frame.len'][0:120]
            
            BPS_list = list(map(_replaceitem, BPS_list))
            lenBPS = len(BPS_list)
            if lenBPS < 120:
                print("len is less")
                diff = 120- lenBPS
                for d in range(diff):
                    BPS_list.append(0)
            BPS_list.append("PcapLocalDrive")
            writer.writerow(BPS_list)

    
    plt.close()
    x = []
    y = []
    array = []
    with open('E:\\ads\\toolV1.2\\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv','r') as csvfile:
        plots = csv.reader(csvfile, delimiter = ',')
        
        for col in plots:
            col = col[0:-1]
            array = col
            for i in range(len(col)):
                
                x.append(i)
                y.append(int(col[i]))
    
    plt.rcParams["figure.figsize"] = (7,2)
    plt.rcParams['figure.dpi'] = 600
    plt.bar(x, y, color = 'black', width = 0.72 )
    plt.xlabel('Time(s)')
    plt.ylabel('Bytes per second')
    plt.title('Bytes per second')
    plt.plot()
    fig=plt.gcf()
    buf = io.BytesIO()
    fig.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri = urllib.parse.quote(string)
    df =  pd.DataFrame (array, columns = ['column_name'])
    df['column_name'] = df['column_name'].astype(int)
    mean = df['column_name'].mean()
    std = df['column_name'].std()
    firstQuartile =  df.column_name.quantile([0.25]).to_string(index=False)
    median = df.column_name.quantile([0.50]).to_string(index=False)
    secondQuartile =  df.column_name.quantile([0.75]).to_string(index=False)
    plt.close()


    #bytes per peak
    xx = []
    yy = []

    sum=0
    with open('E:\\ads\\toolV1.2\\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv','r') as csvfile:
        plots = csv.reader(csvfile, delimiter = ',')
        print(plots)
        for col in plots:
            print(col)
            col = col[0:-1]
            
            for i in range(len(col)):
                
                if i<len(col)-1:   
                    if int(col[i+1])!= 0 :
                        sum=sum+int(col[i])
                    else:
                        sum=sum+int(col[i])
                        if sum!=0:
                            yy.append(sum)
                            
                            sum=0
                else:
                    sum=sum+int(col[i])
                    yy.append(sum)
    xx=range(1,len(yy)+1)                
    plt.rcParams["figure.figsize"] = (7,2)
    plt.rcParams['figure.dpi'] = 600
    plt.bar(xx,yy, color = 'black', width = 0.72 )
    plt.xlabel('Time(s)')
    plt.ylabel('Bytes per Peak')
    plt.title("Bytes per Peak")
    plt.plot()
    figgggggg=plt.gcf()
    buf = io.BytesIO()
    figgggggg.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri5 = urllib.parse.quote(string)
    BPS_list.clear()
    plt.close()

    
    #packets per second 
    with open(r"E:\\ads\\toolV1.2\\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
           
        
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        
        file = file_name
        newBPS_list = []
        newBPS_list2= []
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
            
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        packet_per_second=source_address.resample("s", on='frame.time_epoch').count()
    
        BPS_list=packet_per_second['frame.len'][0:120]
        
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 120:
            print("len is less")
            diff = 120- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        plt.rcParams["figure.figsize"] = (7,2)
        plt.rcParams['figure.dpi'] = 600
        plt.bar(range(len(BPS_list)),BPS_list, color = 'black', width = 0.72 )
        plt.title('Packets per second')
        plt.xlabel('Time(s)')
        plt.ylabel('Packet per second')
        plt.plot()
        figg=plt.gcf()
        buf = io.BytesIO()
        figg.savefig(buf,format='png')
        buf.seek(0)
        string = base64.b64encode(buf.read())
        uri1 = urllib.parse.quote(string)
        BPS_list.clear()
        plt.close()
    
    
        #writer.writerow(BPS_list)

    


    #instantaneous graph
    with open(r"E:\\ads\\toolV1.2\\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
           
       
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
    
        file = file_name
        newBPS_list = []
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
            
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        bytes_per_second=source_address.resample("100ms", on='frame.time_epoch').sum()
    
        BPS_list=bytes_per_second['frame.len'][0:1200]
        
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 1200:
            print("len is less")
            diff = 1200- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        for data in BPS_list:
            temp = (data/1024)
            newBPS_list.append(temp)
        plt.rcParams["figure.figsize"] = (7,2)
        plt.rcParams['figure.dpi'] = 600
        plt.plot(newBPS_list)
        plt.title('Bytes per 100ms')
        plt.xlabel('Time(ms)')
        plt.ylabel('Instantaneous data (KB)')
        plt.plot()
        figgg=plt.gcf()
        buf = io.BytesIO()
        figgg.savefig(buf,format='png')
        buf.seek(0)
        string = base64.b64encode(buf.read())
        uri2 = urllib.parse.quote(string)
        
        BPS_list.clear() 
        plt.close()

    #short on and off cycle
             
      
    fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
    
    
    newBPS_list = []
    newBPS_list2= []
    file =  file_name
    temp=read_pcap(file, fields, timeseries=True, strict=True)
    temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
    
    source_address=temp[temp["ip.dst"] == mostOccuredIp]
    bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()

    BPS_list=bytes_per_second['frame.len'][0:120]

    BPS_list = list(map(_replaceitem, BPS_list))
    lenBPS = len(BPS_list)
    if lenBPS < 120:
        print("len is less")
        diff = 120- lenBPS
        for d in range(diff):
            BPS_list.append(0)
    for data in BPS_list:
        temp = (data/1024)/1024
        newBPS_list.append(temp)
    cdf = np.cumsum(newBPS_list)
    plt.plot(cdf)
    plt.title('Data downloaded')
    plt.xlabel('Time(s)')
    plt.ylabel('Download Amount (MB)')
    plt.rcParams["figure.figsize"] = (7,2)
    plt.rcParams['figure.dpi'] = 600
    figggg=plt.gcf()
    buf = io.BytesIO()
    figggg.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri3 = urllib.parse.quote(string)
    BPS_list.clear()
    plt.close()
    BPS_list.clear()


    #normalized graph
    fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
    
    
    newBPS_list = []
    newBPS_list2= []
    file =  file_name
    temp=read_pcap(file, fields, timeseries=True, strict=True)
    temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
    
    source_address=temp[temp["ip.dst"] == mostOccuredIp]
    bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()

    BPS_list=bytes_per_second['frame.len'][0:120]

    BPS_list = list(map(_replaceitem, BPS_list))
    lenBPS = len(BPS_list)
    if lenBPS < 120:
        print("len is less")
        diff = 120- lenBPS
        for d in range(diff):
            BPS_list.append(0)
    for data in BPS_list:
        temp = (data/1024)/1024
        newBPS_list.append(temp)
    cdf = np.cumsum(newBPS_list)
    normalized = (cdf-min(cdf))/(max(cdf)-min(cdf))
    plt.plot(normalized)
    plt.title('Cumulative downloaded data')
    plt.xlabel('Time(s)')
    plt.ylabel('CDF')
    plt.rcParams["figure.figsize"] = (7,2)
    plt.rcParams['figure.dpi'] = 600
    figgggg=plt.gcf()
    buf = io.BytesIO()
    figgggg.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri4 = urllib.parse.quote(string)
    BPS_list.clear()
    plt.close()
    BPS_list.clear()
    #model predication
    #------------------- df  = list of BPS -----------------
    BPS_list=[]
    with open("E:\\ads\\toolV1.2\mysite\\nonVpnCsv\\NonVPN_PCAPs_1300ms.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        
        
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        
        file = file_name
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
        source_address=temp[temp["ip.dst"] == mostOccuredIp]
        bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
        BPS_list=bytes_per_second['frame.len'][0:120]
        
        BPS_list = list(map(_replaceitem, BPS_list))
        lenBPS = len(BPS_list)
        if lenBPS < 120:
            print("len is less")
            diff = 120- lenBPS
            for d in range(diff):
                BPS_list.append(0)
        BPS_list.append("PcapFromLocalDrive")
        writer.writerow(BPS_list)
    
    array = BPS_list[0:120]

    #dict of links
    linksDict = {"link1":"Learn Object Oriented Programming in 10 minutes (Java)","link111":"Arslan Ash vs Knee - EVO 2019 Grand Finals - Tekken 7","link112":"How To Make Marble Cake At Home in Urdu I Marble Cake Recipe I No Oven Cake Recipe I Marble Tea Cake","link113":"Mozzarella Cheese Recipe By ijaz Ansari | How To Make Mozzarella Cheese At Home | No Rennet |","link114":"Extra Crispy Fried Chicken Recipe By Food Fusion (Ramzan Special)","link115":"10 Most Expensive Things Dwayne The Rock Johnson Owns - MET Ep 14","link116":"Shahid Afridi Home Tour | Exclusive Video","link117":"Ek Sharabi Jo Sharab Se Roza Iftar Krta Tha | Latest Ramadan Bayan by Maulana Tariq Jameel 2017","link118":"Daniel Bryan & Roman Reigns vs. Seth Rollins Big Show Kane & J&J Security: Raw February 9 2015","link119":"Spintop Snipers | Amazing Top Trick Shots!","link120":"Random Acts of Kindness - Faith In Humanity Restored #3","link121":"Sony - World's First Smartphone To Do This","link122":"AVENGERS ENDGAME Becoming Fat Thor Behind the Scenes Bonus Clip (2019) Chris Hemsworth Move HD","link123":"ScaleTrains BNSF HO Scale Dash 9 C44-9W Unboxing","link124":"Xiaomi Mi Mix Alpha Impressions: The Wraparound Display!","link125":"Shan-e-Iftar - Shan E Dastarkhwan [Chicken Parmesan] - 23rd April 2021 - Chef Farah","link126":"Latest Trouser Design 2021 | Capri Design 2021 | Plazo Pant Design","link128":"VW Amarok Tackling Gunshot Creek Sept 2015","link129":"Eau De Bean | Mr Bean Cartoon Season 3 | NEW FULL EPISODE | Season 3 Episode 12 | Mr Bean Official","link2":"Why You Shouldn’t Learn Python In 2021","link3":"10 LATEST TECHNOLOGY INVENTIONS ▶ Smart Vehicle You Must See","link31":"Can My Water Cooled Raspberry Pi Cluster Beat My MacBook?","link32":"LIFE IN RAMZAN! | COMEDY VIDEO","link33":"Russell Shakib & Malan Join in | Zero Tolerance required for PSL Protocols","link34":"TensorFlow.js Quick Start","link35":"you need to learn Virtual Machines RIGHT NOW!! (Kali Linux VM Ubuntu Windows)","link36":"Coding Interview | Software Engineer @ Bloomberg (Part 1)","link38":"Amazing Brathwaite 100! | West Indies v New Zealand - Match Highlights | ICC Cricket World Cup 2019","link39":"Ferocious Dinosaur Moments | Top 5 | BBC Earth","link40":"10 Latest NEW TECH GADGETS AND INVENTIONS 2020 | Available On Amazon | You Can Buy in ONLINE STORE","link41":"Ranking push of my team's OP Play video | Many Hackers | PUBG MOBILE","link85":"AIRPLANE Bean | Bean Movie | Funny Clips | Mr Bean Official","link86":"Mini LED cube with 54 pixel WiFi & gyroscope | SMT hotplate soldering | Pikocube v2.0","link87":"ASMR Video | Build Modern Glass Elevator For Underground And Rooftop Infinity Swimming Pool","link88":"NEW BEST LANDING IN MILITARY BASE","link89":"Random Facts Around The World | Part 57 | Urdu / Hindi","link90":"How THANOS Knew TONY In Avengers: Infinity War? | Super Questions Ep. 5 | Super Access","link91":"Data Center NETWORKS (what do they look like??) // FREE CCNA // EP 7","link92":"New Ghar Saman Shift Karna Shuru Kar diya","link93":"2v4 CLUTCH FOR THE WWCD • PMPL FINALS • 2 MAN CHICKEN DINNER •","link94":"MAKING A SNEAKER ROOM IN MY NEW HOUSE!","link95":"5 Richest Kids Of Pakistan | TOP X TV","link96":"Levels of Ultra Instinct (1% - 50% - 100%)"}

    # ensemble list
    ensembleList = []

    #BPS model
    predict_name = BPSModel(array)
    ensembleList.append(predict_name)
    print("predicted by BPS is ", predict_name)
    predict_name = linksDict[predict_name]

    #detect BPS - Classes (VPN vs NonVPN)
    #predict_name_BPS_Classes = BPSClassesVPNvsNonVPN(array)
    #print("predicted by BPS with classes is ", predict_name_BPS_Classes)
    #predict_name_BPS_Classes = linksDict[predict_name_BPS_Classes]
    
    #BPS - Without Classes (VPN vs NonVPN)
    predict_name_BPS_Without_Classes = BPSWithoutClassesVPNvsNonVPN(array)
    print("predicted by BPS without classes is ", predict_name_BPS_Without_Classes)
    
    #DF model 
    predict_name_DF = testingWithFingerprint(array)
    ensembleList.append(predict_name_DF)
    print("predicted by df is ", predict_name_DF)
    predict_name_DF = linksDict[predict_name_DF]
    
    #PAT model
    linkNumberr = "Local Storage"
    PATBpsList = generate_PAT(file_name,linkNumberr)
    predict_name_PAT = preditWithPATFingerprint(PATBpsList, linkNumberr)
    ensembleList.append(predict_name_PAT)
    print("predicted by PAT is ", predict_name_PAT)
    predict_name_PAT = linksDict[predict_name_PAT]
    

    #flowpic
    predict_name_FP,uriFP = testingWithFlowpic(file_name)
    print("predicted by fp is ", predict_name_FP)
    predict_name_FP = linksDict[predict_name_FP]
    
    #ensemble
    predict_name_ensemble = ensemble(ensembleList)
    print(ensembleList)
    print("predicted by ensemble is ", predict_name_ensemble)
    if predict_name_ensemble != "Ensemble failed":
        predict_name_ensemble = linksDict[predict_name_ensemble]

    

    


    return render(request ,"index.html",{"something":True,"sum":file_name,'data':uri,"mean":mean,"std":std,"qur1":firstQuartile,"median":median,"qur2":secondQuartile,"packetsPerSecond":uri1,"Instantaneous":uri2,"shortOnOffCycle":uri3,"normalized":uri4,"bytesPerPeak":uri5,"flowPicImg":uriFP,"predictedName":predict_name,"bpsWithoutClasses":predict_name_BPS_Without_Classes,"DF":predict_name_DF,"FP":predict_name_FP,"PAT":predict_name_PAT,"ensemble":predict_name_ensemble})