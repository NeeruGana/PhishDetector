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
import numpy as np









def getDomain(url):  
    domain = urlparse(url).netloc
    if re.match(r"^www.",domain):
        domain = domain.replace("www.","")
    return domain

#IP in url
def ipinurl(url):
    try:
        ipaddress.ip_address(url)
        ip=1
    except:
        ip=0
        return ip

#@ in url
def splchar(url):
    if "@" in url:
        sc=1
    else:
        sc=0
    return sc

def dots(url):
    
    
    n=url.count(".")
    if n>4:
        c=1
    else:
        c=0
    return c
#dots('https://neerugana.github.io')

#Length of URL

def urllength(url):
    if len(url)>66:
        urll=1
    else:
        urll=0
    return urll

#Depth of url --calculates the no of pages based on /

def urldepth(url):
    n=urlparse(url).path.split('/')
    depth=0
    for i in range(len(n)):
        if len(n[i])!=0:
            depth+=1
    return depth

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"



def tinyurl(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0


def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1           
    else:
        return 0  
    

#Redirection with //
def redir(url):
    #nani='http:////nani.com/neeraj/neeraj'
    fs=url.rfind('//');
    #ns=nani.rfind('//');
    if fs>6:
        #print("Fish")
        return 1
    else:
        #print("Benign")
        return 0

def domainAge(domain_name):
    try:
        cr_time=domain_name.creation_date
        ex_time = domain_name.expiration_date
        diff=(ex_time - cr_time)
        age= abs(diff).days
    except:
        return 1
    if(age/30 <= 6):
        return 1
    else:
        return 0

#def dns(domain_name):
 
 #   dns = 0
  
  #  try:
  #      domain_name = whois.query(urlparse(url).netloc)
  #  except:
  #      return 1
    

#Domain End


def domainEnd(domain_name):
    
    try:
        #domain=whois.query(do)
        #creation_date=domain.creation_date
        #print(creation_date.replace(tzinfo=None))
        today = datetime.now()
        exp_time=domain_name.expiration_date
        #print(exp_time)
        #n=today.replace(tzinfo=None)
        #print(n)
        diff = (exp_time - today)
        dif=abs(diff).days
    
    
    except:
        return 1
    
    if(dif/30 <6):
        return 1
    else:
        return 0


def featureExtraction(url):
    features=[]
    #hostname = get_hostname_from_url(url)
    features.append(getDomain(url))
    features.append(ipinurl(url))
    features.append(splchar(url))
    features.append(dots(url))
    features.append(urllength(url))
    features.append(urldepth(url))
    features.append(tinyurl(url))
    features.append(prefixSuffix(url))
    #features.append(dns(url))
    dns = 0
    try:
        domain_name = whois.query(urlparse(url).netloc)
    except:
        dns = 1

    
    features.append(redir(url))
    #features.append(web_traffic(url))
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))
    features.append(dns)
    
    #features.append(label)
    #print(features)
    
    
    return features



    
#data=np.array([[ipinurl,splchar,dots,urllength,urldepth,tinyurl,prefixSuffix,redir,domainAge,domainEnd,dns]])
#print(features)

#print(data)


f2=open("test.txt","r")
url=f2.read()
f2.close()
print(url)


final = featureExtraction(url)
print(final)