# libraries used
import json

from nltk.corpus import stopwords 
from nltk.tokenize import word_tokenize
from nltk.tokenize.treebank import TreebankWordDetokenizer
from nltk.stem import PorterStemmer
import re

# reduce text to comparable format
def clean_text(text):
    # text preprocessing
    # reference https://www.kdnuggets.com/2018/11/text-preprocessing-python.html
    
    # convert to lower case
    text = text.lower()

    # remove non-alphanumeric
    # preserve spaces and @ 
    text = re.sub(r'[^a-zA-Z0-9 ]', '', text)

    # remove bounding spaces
    text = text.strip()

    # tokenize
    tokens = word_tokenize(text)
    
    # remove stop words
    # stemming
    stopWords = set(stopwords.words('english'))
    stemmer = PorterStemmer()
    tokens = [stemmer.stem(x) for x in tokens if x not in stopWords]

    # detokenize
    detokenizer = TreebankWordDetokenizer()
    text = detokenizer.detokenize(tokens)
    
    return text

# load data from file
def load_data():
    # read tweets
    with open('../descriptions_io.json', 'r') as inFile:
        data = json.loads(inFile.read())

    for deviceName in data.keys():
        for deviceData in data[deviceName]:
            description = deviceData['description']
            cleanedDescription = clean_text(description)
            deviceData['cleaned_description'] = cleanedDescription

            iOList = deviceData['i/o']
            if(len(iOList) == 0):
                # no processing for empty list
                continue

            cleanedIOList = []
            for pair in iOList:
                pairInput = pair.split('->')[0]
                pairOutput = pair.split('->')[1]
                cleanedPairInput = clean_text(pairInput)
                cleanedPairOutput = clean_text(pairOutput)
                cleanedPair = cleanedPairInput + "->" + cleanedPairOutput
                cleanedIOList.append(cleanedPair)
            deviceData['cleaned_i/o'] = cleanedIOList





            
description = "An issue was discovered in D-Link 'myDlink Baby App' version 2.04.06. Whenever actions are performed from the app (e.g., change camera settings or play lullabies), it communicates directly with the Wi-Fi camera (D-Link 825L firmware 1.08) with the credentials (username and password) in base64 cleartext. An attacker could conduct an MitM attack on the local network and very easily obtain these credentials."

#cleanedDescription = clean_text(description)
#print(cleanedDescription)

load_data()
