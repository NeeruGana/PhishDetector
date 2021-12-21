from flask import Flask,request,render_template
import pickle
import numpy as np
from urllib.parse import urlparse,urlencode
import ipaddress
import re
#DOMAIN BASED

import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime, timezone
import time
import requests
import pandas as pd






app=Flask(__name__)


@app.route('/')
  
def index():
	return render_template('index.html')
	

@app.route('/predict',methods=['POST'])

def predict():
	if request.method=='POST':
		
		url=request.form['url']
		#global furl
		#furl=url
		f1=open("test.txt","w")
		f1.write(url)
		f1.close()
		from FeatureExtration import final
		
		ipinurl=final[1]
		#splchar=request.form['splchar']
		splchar=final[2]
		#dots=request.form['dots']
		#urllength=request.form['urllength']
		#urldepth=request.form['urldepth']
		#tinyurl=request.form['tinyurl']
		#prefixSuffix=request.form['prefixSuffix']
		#redir=request.form['redir']
		#domainAge=request.form['domainAge']
		#domainEnd=request.form['domainEnd']
		#dns=request.form['dns']
		dots=final[3]
		urllength=final[4]
		urldepth=final[5]
		tinyurl=final[6]
		prefixSuffix=final[7]
		redir=final[8]
		domainAge=final[9]
		domainEnd=final[10]
		dns=final[11]
		data=np.array([[ipinurl,splchar,dots,urllength,urldepth,tinyurl,prefixSuffix,redir,domainAge,domainEnd,dns]])
		model = pickle.load(open('rfc.pickle.dat', 'rb'))
		pred = model.predict(data)
    
	return render_template('index.html', label=pred)	
		


 	
if __name__=='__main__':
	app.run(debug=True) 
 
