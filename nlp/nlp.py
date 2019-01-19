# libraries used
import json

import nltk
from nltk.corpus import stopwords 
from nltk.tokenize import word_tokenize
from nltk.tokenize.treebank import TreebankWordDetokenizer
from nltk.stem import PorterStemmer
from sklearn.feature_extraction.text import TfidfVectorizer
import pytextrank

import re
import numpy as np
import json

import sys
import os

MAX_INPUT_LENGTH = 3

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
# first pass on data
def load_data():
    # read tweets
    with open('../descriptions_io.json', 'r') as inFile:
        data = json.loads(inFile.read())

    allCleanedDescriptions = []
    for deviceName in sorted(data.keys()):
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

# accumulate and process
[data, allCleanedDescriptions] = load_data()

# compute tf idf scores
tfIdfVectorizer = TfidfVectorizer()
tfIdfMatrix = tfIdfVectorizer.fit_transform(allCleanedDescriptions)
features = tfIdfVectorizer.get_feature_names()
featuresIdf = tfIdfVectorizer.idf_

# get all features in reverse idf order
# idf can be a heuristic to extract important terms
sortedIndexes = np.argsort(featuresIdf)[::-1]

cleanedDescriptionsIndex = -1
for deviceName in sorted(data.keys()):
    for deviceData in data[deviceName]:
        cleanedDescription = deviceData['cleaned_description']
        cleanedDescriptionsIndex += 1
        tokens = cleanedDescription.split(' ')
        tfIdfValues = []

        for token in tokens:
            # mandate minimum token length of 2 to remove invalid tokens
            if(len(token) == 1):
                continue
            
            # all tokens that reach this line can be found in features
            tokenIndex = features.index(token)
            tfIdfValue = tfIdfMatrix[cleanedDescriptionsIndex,tokenIndex]            
            tfIdfValues.append(tfIdfValue)

        # use tf idf to extract important terms
        sortedIndexes = np.argsort(tfIdfValues)[::-1]
        sortedTokens = [tokens[index] for index in sortedIndexes]

        # use top k terms here
        # top k terms here will contain a mix of input and output terms for use in i/o
        deviceData['sorted_tokens'] = sortedTokens

        posTags = nltk.pos_tag(word_tokenize(cleanedDescription))
        deviceData['pos_tags'] = posTags
        filteredPosTags = [x for x in posTags if 'NN' not in x[1]]
        #filteredPosTags = [x for x in posTags if 'NN' in x[1]]


        #print(sortedTokens)
        #print(
        #sys.exit()
        
        # order filtered pos tags based on tfidf values
        filteredPosTags.sort(key=lambda x: sortedTokens.index(x[0]))
        deviceData['filtered_pos_tags'] = filteredPosTags
        
for item in data:
    for subItem in data[item]:
        if('cleaned_i/o' not in subItem.keys()):
            # consider invalid
            continue

        print('###############')
        print('description:', subItem['description'])
        #print(subItem['cleaned_description'])
        #print(subItem['i/o'])
        #print(subItem['cleaned_i/o'])
        #print(subItem['pos_tags'])
        #print(subItem['filtered_pos_tags'])
        #print(subItem['sorted_tokens'])
        
        # using pytextrank
        # reference https://github.com/ceteri/pytextrank/issues/18
        
        # raw input
        subItemJSON = {'id': subItem['id'], 'text': subItem['description']}
        subItemJSON = json.dumps(subItemJSON)
        with open('sub_item.json', 'w') as outFile:
            outFile.write(subItemJSON)

        # stage 1
        with open('stage1_output.json', 'w') as outFile:
            for graf in pytextrank.parse_doc(pytextrank.json_iter('sub_item.json')):
                outFile.write("%s\n" % pytextrank.pretty_print(graf._asdict()))

        # stage 2
        graph, ranks = pytextrank.text_rank('stage1_output.json')
        pytextrank.render_ranks(graph, ranks)
        rlLists = []
        print('key phrases:')
        with open('stage2_output.json', 'w') as outFile:
            for rl in pytextrank.normalize_key_phrases('stage1_output.json', ranks):
                rlList = eval(pytextrank.pretty_print(rl))
                rlLists.append(rlList)
                print(rlList)

        # filter results based on pos
        # this is a heuristic
        filteredRlLists = [x for x in rlLists if 'nn' not in x[-2]]

        if(len(filteredRlLists) == 0):
            # invalid case
            continue

        # cleanup
        os.system('rm -f sub_item.json stage1_output.json stage2_output.json graph.dot')

        # the first item in filteredRLLists is a heuristic for 'i'
        heuristic = filteredRlLists[0][0]
        
        # stem each token in heuristic
        # use highest rated token based on sorted tokens from tfidf        
        heuristicTokens = clean_text(heuristic).split(' ')
        heuristicTokens.sort(key=lambda x: subItem['sorted_tokens'].index(x))

        # only use top few tokens
        # rearrange tokens in the order of cleaned heuristic, so that the phrase makes more sense
        heursiticTokens = heuristicTokens[:MAX_INPUT_LENGTH]
        cleanedHeuristic = clean_text(heuristic)
        heuristicTokens.sort(key=lambda x: cleanedHeuristic.split(' ').index(x))
        detokenizer = TreebankWordDetokenizer()
        iOInput = detokenizer.detokenize(heuristicTokens)

        print('heuristic:', heuristic)
        print('i/o input:', iOInput)

        print('###############')
