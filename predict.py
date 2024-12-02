import numpy as np
from flask import Flask, request, jsonify, render_template
import pickle

model = pickle.load(open('evmod','rb'))

@app.route('/predict',methods = [ 'POST'])
def predict():
    v=[]
    Tesla1 = [4.4,233,485,366,493,82,4694,1849,1443,2875,2232,388,561,0,0,1,0,0,1,0,0]
    Tesla2 = [3.3,261,460,377,660,82,4694,1849,1443,2875,2232,388,561,0,0,0,1,0,1,0,0]
    BMW = [5.7,190,470,250,430,83.9,4783,1852,1448,2856,2605,555,470,1,0,0,0,0,0,0,1]
    Volkswagen = [7.9,160,450,150,310,82,4261,1809,1568,2771,2300,447,385,0,0,0,0,1,0,0,1]
    Polestar = [7.4,160,425,170,330,78,4607,1800,1479,2735,2490,496,405,0,1,0,0,0,0,1,0]
    features = [int(x) for x in request.form,values()]
    v=[]
    if (features[0]==1):
        v.append(features[1])
        int_features = v+Tesla1
    elif (features[0]==2):
        v.append(features[1])
        int_features = v+Tesla2
    elif (features[0]==3):
        v.append(features[1])
        int_features = v+BMW
    elif (features[0]==4):
        v.append(features[1])
        int_features = v+Volkswagen
    elif (features[0]==5):
        v.append(features[1])
        int_features = v+Polestar
    final_features = [np.array(int_features)]
    prediction = model.predict(final_features)
    val = int(prediction[0])
    
    return render_template('',prediction_text='Estimated car range in Km --> {}'.f)
        
    