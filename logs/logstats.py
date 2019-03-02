import csv
from pylab import *
import numpy as np

echo_ipv4 = "10.0.0.93"
printer_ipv4 = "10.0.0.114"
wemo_ipv4 = "10.0.0.121"
roku_ipv4 = "10.0.0.20"
google_ipv4 = "10.0.0.150"



ssl = {}

incoming = {}
outgoing = {}

gh_calls = []
echo_calls = []
wemo_calls = []
hp_calls = []
roku_calls = []

num_steps = 150

with open('Jan14.csv', 'r') as csvfile:
    with open ('Jan14.csv', 'r') as csvfile1:
        reader = csv.reader(csvfile,delimiter=',')
        reader1 = csv.reader(csvfile1,delimiter=',')
        endtime = list(reversed(list(reader1)))[0][1]
        timestep = float(endtime)/float(num_steps)
        print (timestep)
        step_ind = 1
        num_gh_calls = num_echo_calls = num_wemo_calls = num_hp_calls = num_roku_calls = 0
        for row in reader:
            if row[2] == echo_ipv4 or row[3] == echo_ipv4:
                num_echo_calls += 1
            if row[2] == printer_ipv4 or row[3] == printer_ipv4:
                num_hp_calls += 1
            if row[2] == wemo_ipv4 or row[3] == wemo_ipv4:
                num_wemo_calls += 1
            if row[2] == roku_ipv4 or row[3] == roku_ipv4:
                num_roku_calls += 1
            if row[2] == google_ipv4 or row[3] == google_ipv4:
                num_gh_calls += 1
            if float(row[1]) > timestep*step_ind:
                step_ind+=1
                gh_calls.append(num_gh_calls)
                echo_calls.append(num_echo_calls)
                wemo_calls.append(num_wemo_calls)
                hp_calls.append(num_hp_calls)
                roku_calls.append(num_roku_calls)
                num_gh_calls = num_echo_calls = num_wemo_calls = num_hp_calls = num_roku_calls = 0
            if len(row) == 7: # Has SSL
                print("SSL")
                try:
                    ssl[row[2]] = ssl[row[2]] + 1
                except:
                    ssl[row[2]] = 1
            try:
                incoming[row[3]] = incoming[row[3]]+1
            except:
                incoming[row[3]] = 1
            try:
                outgoing[row[2]] = outgoing[row[2]]+1
            except:
                outgoing[row[2]] = 1
        gh_calls.append(num_gh_calls)
        echo_calls.append(num_echo_calls)
        wemo_calls.append(num_wemo_calls)
        hp_calls.append(num_hp_calls)
        roku_calls.append(num_roku_calls)
        print incoming, outgoing

s = range(num_steps)

semilogy(s, gh_calls)
semilogy(s, echo_calls)
semilogy(s, wemo_calls)
semilogy(s, hp_calls)
semilogy(s, roku_calls)
semilogy()
xlabel('Hours')
ylabel('Traffic Events')
title('Usage over time')
legend(['Google Home', 'Amazon Echo', 'Belkin Wemo', 'HP Printer', 'Roku'], loc=2, bbox_to_anchor=(1.05, 1),borderaxespad=0.)
grid(False)
savefig('usageJan14.png', bbox_inches='tight')

