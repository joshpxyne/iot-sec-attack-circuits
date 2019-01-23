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
            
    # return modified data
    # cleaned components have been added
    return [data, allCleanedDescriptions]

def do_tf_idf(data, allCleanedDescriptions):
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
            # sort them in descending order of score
            sortedIndexes = np.argsort(tfIdfValues)[::-1]
            sortedTokens = [tokens[index] for index in sortedIndexes]
            deviceData['sorted_tokens'] = sortedTokens

    return data

def do_heuristic(subItem, filteredRlLists):
    # the first item in filteredRLLists is a heuristic for 'i'
    heuristic = filteredRlLists[0][0]

    # stem each token in heuristic
    # use highest rated token based on sorted tokens from tfidf
    # find the closest thing that looks like token in sorted list
    # note: heuristic token may not be in sorted tokens. this is assumed as default
    heuristicTokens = clean_text(heuristic).split(' ')
    tokenScores = {}
    for item in heuristicTokens:
        tokenScores[item] = -1
        matches = [y for y in subItem['sorted_tokens'] if y in item]

        if(len(matches) > 0):
            match = matches[0]
            tokenScores[item] = subItem['sorted_tokens'].index(match)

    heuristicTokens.sort(key=lambda x: tokenScores[x])

    # only use top few tokens
    # rearrange tokens in the order of cleaned heuristic, so that the phrase makes more sense
    heuristicTokens = heuristicTokens[:MAX_INPUT_LENGTH]
    cleanedHeuristic = clean_text(heuristic)
    heuristicTokens.sort(key=lambda x: cleanedHeuristic.split(' ').index(x))

    # convert input back to heuristic syntactics
    # replace each token with corresponding word from heuristic with maximum overlap
    # use edit distance
    matches = []
    for token in heuristicTokens:
        items = []
        for item in heuristic.split(' '):
            distance = nltk.edit_distance(token, item)
            items.append((distance, item))
        items.sort()

        # use the first item that is not already in the list
        for item in items:
            if(item[1] not in matches):
                matches.append(item[1])
                break

    detokenizer = TreebankWordDetokenizer()
    iOItem = detokenizer.detokenize(matches)

    return [heuristic, iOItem]

def do_pytextrank(data):
    for item in data:
        for subItem in data[item]:
            print('###############')
            print('description:', subItem['description'])

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

            # cleanup
            os.system('rm -f sub_item.json stage1_output.json stage2_output.json graph.dot')

            # input filter results based on pos
            # this is a heuristic
            filteredRlLists = [x for x in rlLists if 'nn' not in x[-2]]
            if(len(filteredRlLists) == 0):
                # invalid case
                continue
            else:
                [heuristic, iOItem] = do_heuristic(subItem, filteredRlLists)
                print('heuristic:', heuristic)
                print('i/o input:', iOItem)

            # input filter results based on pos
            # this is a heuristic
            filteredRlLists = [x for x in rlLists if 'nn' in x[-2]]
            if(len(filteredRlLists) == 0):
                # invalid case
                continue
            else:
                [heuristic, iOItem] = do_heuristic(subItem, filteredRlLists)
                print('heuristic:', heuristic)
                print('i/o output:', iOItem)

            print('###############')


def main():
    # accumulate and process data            
    [data, allCleanedDescriptions] = load_data()
    data = do_tf_idf(data, allCleanedDescriptions)
    do_pytextrank(data)

main()
