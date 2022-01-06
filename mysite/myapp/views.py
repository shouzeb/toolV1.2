import csv
import os.path
import subprocess
import time
import datetime
import os
import sys
import shutil
import matplotlib
from numpy import string_
matplotlib.use('Agg')
import numpy as np
import urllib,base64
import matplotlib.pyplot as plt
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
import pandas as pd 
plt.ioff()
from keras.models import load_model
from scapy.all import *


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
        link100_duration = 120
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
    model = load_model(r'E:\\ads\\modelfiles\\NonVPN Model\\NonVPN.h5')
    l_temp=pd.read_pickle(r'E:\\ads\\modelfiles\\NonVPN Model\\NonVPN.pkl')

    array = BPS_list[0:120]

    #BPS model
    x = []
    df =  pd.DataFrame (array, columns = ['column_name'])
    df['column_name'] = df['column_name'].astype(int)
    #name = str(df[i,121:].values.tolist())
    x = df['column_name'] #
    v=4459355

    x1=np.vectorize(norm)(x,v)

    labels = np.asarray(l_temp, dtype = np.int8)
    x3 = x1.reshape(1,120,1)
    y_pred1 = model.predict(x3)
    l_temp.loc[-1]=y_pred1[0]
    predict_name = l_temp.loc[-1].idxmax()

    #detect BPS - Classes (VPN vs NonVPN)

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
    #print("BPS - Classes (VPN vs NonVPN): ",predict_name_BPS_Classes)


    #BPS - Without Classes (VPN vs NonVPN)

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
    #print("BPS - Without Classes (VPN vs NonVPN): ",predict_name_BPS_Without_Classes)


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
    

    
    
    return render(request,"page2.html",{'cars':result,'data':uri,"mean":mean,"std":std,"qur1":firstQuartile,"median":median,"qur2":secondQuartile,"packetsPerSecond":uri1,"Instantaneous":uri2,"shortOnOffCycle":uri3,"normalized":uri4,"bytesPerPeak":uri5,"linkNumber":linkNumberr,"predictedName":predict_name,"bpsClasses":predict_name_BPS_Classes,"bpsWithoutClasses":predict_name_BPS_Without_Classes})

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
        link100_duration = 120
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
    model = load_model(r'E:\\ads\\modelfiles\\NonVPN Model\\NonVPN.h5')
    l_temp=pd.read_pickle(r'E:\\ads\\modelfiles\\NonVPN Model\\NonVPN.pkl')

    array = BPS_list[0:120]
    x = []
    df =  pd.DataFrame (array, columns = ['column_name'])
    df['column_name'] = df['column_name'].astype(int)
    #name = str(df[i,121:].values.tolist())
    x = df['column_name'] #
    v=4459355
    x1=np.vectorize(norm)(x,v)
    labels = np.asarray(l_temp, dtype = np.int8)
    x3 = x1.reshape(1,120,1)
    y_pred1 = model.predict(x3)
    l_temp.loc[-1]=y_pred1[0]
    predict_name = l_temp.loc[-1].idxmax()

    #detect BPS - Classes (VPN vs NonVPN)

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
    #print("BPS - Classes (VPN vs NonVPN): ",predict_name_BPS_Classes)


    #BPS - Without Classes (VPN vs NonVPN)

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
    #print("BPS - Without Classes (VPN vs NonVPN): ",predict_name_BPS_Without_Classes)


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
    

    
    
    return render(request,"page2.html",{'cars':result,'data':uri,"mean":mean,"std":std,"qur1":firstQuartile,"median":median,"qur2":secondQuartile,"packetsPerSecond":uri1,"Instantaneous":uri2,"shortOnOffCycle":uri3,"normalized":uri4,"bytesPerPeak":uri5,"linkNumber":linkNumberr,"predictedName":predict_name,"bpsClasses":predict_name_BPS_Classes,"bpsWithoutClasses":predict_name_BPS_Without_Classes})



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
    #folder = "C:\\Users\\user\\Desktop\\ranTests\\pcap\\" + video_name + "\\"+ video_quality
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
    model = load_model(r'E:\\ads\\modelfiles\\NonVPN Model\\NonVPN.h5')
    l_temp=pd.read_pickle(r'E:\\ads\\modelfiles\\NonVPN Model\\NonVPN.pkl')

    array = BPS_list[0:120]
    x = []
    df =  pd.DataFrame (array, columns = ['column_name'])
    df['column_name'] = df['column_name'].astype(int)
    #name = str(df[i,121:].values.tolist())
    x = df['column_name'] #
    v=4459355
    x1=np.vectorize(norm)(x,v)
    labels = np.asarray(l_temp, dtype = np.int8)
    x3 = x1.reshape(1,120,1)
    y_pred1 = model.predict(x3)
    l_temp.loc[-1]=y_pred1[0]
    predict_name = l_temp.loc[-1].idxmax()

    #detect BPS - Classes (VPN vs NonVPN)

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
    #print("BPS - Classes (VPN vs NonVPN): ",predict_name_BPS_Classes)


    #BPS - Without Classes (VPN vs NonVPN)
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
    l_temp.loc[-1] = y_pred1[0]
    predict_name_BPS_Without_Classes = l_temp.loc[-1].idxmax()
    #print("BPS - Without Classes (VPN vs NonVPN): ",predict_name_BPS_Without_Classes)

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



    


    return render(request ,"index.html",{"something":True,"sum":file_name,'data':uri,"mean":mean,"std":std,"qur1":firstQuartile,"median":median,"qur2":secondQuartile,"packetsPerSecond":uri1,"Instantaneous":uri2,"shortOnOffCycle":uri3,"normalized":uri4,"bytesPerPeak":uri5,"predictedName":predict_name,"bpsClasses":predict_name_BPS_Classes,"bpsWithoutClasses":predict_name_BPS_Without_Classes})