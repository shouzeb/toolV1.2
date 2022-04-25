import pandas as pd
import csv
from csv import DictWriter
import numpy as np
from keras.models import load_model




def norm(x,v):
  return x/v
def tostring1(x):
  return '{:.2f}'.format(x)

    

def preditWithFingerprint(BPS_list,name,currentdate):
    # data to be written row-wise in csv fil
    data = [BPS_list]
      
    # opening the csv file in 'w+' mode
    file = open(r"D:\Ammar\OneDrive - Higher Education Commission\9 - Enssemble\Results\test_BPS test.csv", 'w', newline ='')
      
    # writing the data into the file
    with file:    
        write = csv.writer(file)
        write.writerows(data) 
    file.close()
        
    dataorig =  pd.read_csv(r"D:\Ammar\OneDrive - Higher Education Commission\9 - Enssemble\Results\test_BPS test.csv",header=None)
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
       # dif = (data.iloc[:,i]-data.iloc[:,i-1])                #FP1
        # dif = (data.iloc[:,i]-data.iloc[:,i-1])/data.iloc[:,i-1] #FP2
        dif = (data.iloc[:,i]-data.iloc[:,i-1])**2                #FP3 in works
        difFrame.insert(i-1,str(i),dif)
    
    # for i in range (1,22):
    #     data.insert((2+(i-1)*2),str(i)+"-"+str(i-1),difFrame.iloc[:,i-1])
    difFrame.insert(len(difFrame.columns), None, labels)
    difFrame.to_csv(r"D:\Ammar\OneDrive - Higher Education Commission\9 - Enssemble\Results\DF_iteration_"+currentdate+".csv",mode='a',encoding='utf-8',index=False,header=False)
    
    #print(difFrame.iloc[0])
    result,predict_name = testingWithFingerprint(difFrame.iloc[0],name,currentdate)
    return result,predict_name

# =============================================================================
# runn = 1
# video_name = "link1"
# BPS_list = difFrame.iloc[0]
# count = 0
# =============================================================================

def testingWithFingerprint(BPS_list,video_name,currentdate):
    #checking with BPS model        
    model_path=r"D:\Ammar\OneDrive - Higher Education Commission\9 - Enssemble\Code\NewCode\FPModel\FP3_BPS_769440000000000.h5"      
    model = load_model(model_path)
    l_temp=pd.read_pickle(r"D:\Ammar\OneDrive - Higher Education Commission\9 - Enssemble\Code\NewCode\FPModel\FP3_BPS_test.pkl")
    array = BPS_list[0:21]
# =============================================================================
#     x = []
#     df =  pd.DataFrame (array, columns = ['column_name'])
#     df['column_name'] = df['column_name'].astype(int)
#     #name = str(df[i,121:].values.tolist())
#     x = df['column_name'] #
# =============================================================================
     
    v=769440000000000#change this
    #v=int(model_path.split("_")[-1].split(".")[0])
    
    
    
    x1=np.vectorize(norm)(array,v)
    
    labels = np.asarray(l_temp, dtype = np.int8)
    x3 = x1.reshape(1,21,1)
    y_pred1 = model.predict(x3)
    
    l_temp.loc[-1]=y_pred1[0]
    
    predict_name = l_temp.loc[-1].idxmax()
    print("Video name was ",video_name,". The predicted link is with fingerprinting is : ",predict_name)
    
    
    field_names = ['LinkName','predictedLink','run','prob']
    lis=[]
    count = 0
    if(video_name == predict_name):
        count = 1
    for i in range(43):
        lis.append((l_temp.loc[-1].index[i],'{0:.50f}'.format(l_temp.loc[-1][i])))  
    # Dictionary
    dict={'LinkName':video_name,'predictedLink':predict_name,'run':count,'prob':lis}
     
    
    with open(r"D:\Ammar\OneDrive - Higher Education Commission\9 - Enssemble\Results\Detailed_Results_DF_"+currentdate+'.csv', 'a') as f_object:        
        dictwriter_object = DictWriter(f_object, fieldnames=field_names)
     
        #Pass the dictionary as an argument to the Writerow()
        dictwriter_object.writerow(dict)
     
        #Close the file object
        f_object.close()
    if(video_name == predict_name):
        return 1,predict_name
    else:
        return 0,predict_name
        



