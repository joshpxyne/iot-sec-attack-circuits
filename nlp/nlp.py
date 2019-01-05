# libraries used
import json

from nltk.corpus import stopwords 
from nltk.tokenize import word_tokenize
from nltk.tokenize.treebank import TreebankWordDetokenizer
from nltk.stem import PorterStemmer
import re

from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np

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

    allCleanedDescriptions = []
    for deviceName in data.keys():
        for deviceData in data[deviceName]:
            description = deviceData['description']
            cleanedDescription = clean_text(description)
            deviceData['cleaned_description'] = cleanedDescription
            allCleanedDescriptions.append(cleanedDescription)
            
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

    # return modified data
    # cleaned components have been added
    return [data, allCleanedDescriptions] 
            
[data, allCleanedDescriptions] = load_data()

# compute tf idf scores
tfIdfVectorizer = TfidfVectorizer()
tfIdfMatrix = tfIdfVectorizer.fit_transform(allCleanedDescriptions)
features = tfIdfVectorizer.get_feature_names()
featuresIdf = tfIdfVectorizer.idf_

# get all features in reverse idf order
# idf can be a heuristic to extract important terms
sortedIndexes = np.argsort(featuresIdf)[::-1]

for index in sortedIndexes:
    feature = features[index]
    idf = featuresIdf[index]

    # use top k terms here
    # top k terms here will contain a mix of input and output terms for use in i/o
    #print(feature, idf)

# process cleaned descriptions
for cleanedDescriptionIndex in range(len(allCleanedDescriptions)):
    cleanedDescription = allCleanedDescriptions[cleanedDescriptionIndex]
    tokens = cleanedDescription.split(' ')

    tfIdfValues = []
    for token in tokens:

        # mandate minimum token length of 2 to remove invalid tokens
        if(len(token) == 1):
            continue

        # all tokens that reach this line can be found in features
        tokenIndex = features.index(token)
        tfIdfValue = tfIdfMatrix[cleanedDescriptionIndex,tokenIndex]
        tfIdfValues.append(tfIdfValue)

    # use tf idf to extract important terms
    sortedIndexes = np.argsort(tfIdfValues)[::-1]
    sortedTokens = [tokens[index] for index in sortedIndexes]

    # use top k terms here
    # top k terms here will contain a mix of input and output terms for use in i/o
    #print(sortedTokens)
