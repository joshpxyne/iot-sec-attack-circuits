'''
1 device (amazon echo), 1 CVE (CVE-2018-19189)
Echo exploitability:  0.0481128237946 Echo impact:  0.0299910032388 (Echo exploitability:  0.0629167831126 if frequently online)
Network exploitability:  0.0481128237946 Network impact:  0.0299910032388

1 device (amazon echo), all CVEs
Echo exploitability:  0.168507357322 Echo impact:  0.105604770889 (Echo exploitability:  0.21899477347 if frequently online)
Network exploitability:  0.168507357322 Network impact:  0.105604770889

2 devices
Echo exploitability:  0.187157640205 Echo impact:  0.117455355915
WeMo exploitability:  0.610551402738 WeMo impact:  0.325690709881
Network exploitability:  0.715903238257 Network impact:  0.426818500412

'''


import math
import json

behavioral_uptime = {"always_online": 1.6, "frequently_online": 1.4, "rarely_online": 1.07, "never_online": 1}
behavioral_blacklisted_ip = {"accessed": 5, "not_accessed": 1}
behavioral_ssl = {"not_encrypted":1.5, "encrypted": 1}

integrity = confidentiality = availability = {"NONE": 0, "LOW": .22, "HIGH": .56, "COMPLETE": 1}

echo_non_cve_exp = 6
echo_non_cve_imp = 5
echo_non_cve_bas = 5
wemo_non_cve_exp = 9 
wemo_non_cve_imp = 7
wemo_non_cve_bas = 10

vector = {}

with open("known_cves.json") as cve_json:
        cve_data = json.load(cve_json)
        for device in ["Amazon Echo","Belkin WeMo"]:
            vector[device] = []
            for cve in cve_data[device]:
                print(device,cve["cve"]["CVE_data_meta"]["ID"])
                newEntry = {"id":[cve["cve"]["CVE_data_meta"]["ID"]]}
                try:
                    newEntry["base"] = cve["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                    newEntry["impact"] = cve["impact"]["baseMetricV3"]["impactScore"]
                    newEntry["exploitability"] = cve["impact"]["baseMetricV3"]["exploitabilityScore"]
                    newEntry["availabilityImpact"] = cve["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"]
                    newEntry["integrityImpact"] = cve["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"]
                    newEntry["confidentialityImpact"] = cve["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"]
                except:
                    try:
                        newEntry["base"] = cve["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                        newEntry["impact"] = cve["impact"]["baseMetricV2"]["impactScore"]
                        newEntry["exploitability"] = cve["impact"]["baseMetricV2"]["exploitabilityScore"]
                        newEntry["availabilityImpact"] = cve["impact"]["baseMetricV2"]["availabilityImpact"]
                        newEntry["integrityImpact"] = cve["impact"]["baseMetricV2"]["integrityImpact"]
                        newEntry["confidentialityImpact"] = cve["impact"]["baseMetricV2"]["confidentialityImpact"]
                    except:
                        try:
                            newEntry["base"] = cve["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                            newEntry["impact"] = cve["impact"]["baseMetricV2"]["impactScore"]
                            newEntry["exploitability"] = cve["impact"]["baseMetricV2"]["exploitabilityScore"]
                            newEntry["availabilityImpact"] = cve["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"]
                            newEntry["integrityImpact"] = cve["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"]
                            newEntry["confidentialityImpact"] = cve["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"]
                        except:
                            continue
                
                print(newEntry)
                vector[device].append(newEntry)
print(vector)
'''
One device, one CVE
'''
base_exploitability = vector["Amazon Echo"][2]["exploitability"] # no incoming paths
base_impact = vector["Amazon Echo"][2]["impact"] # no outgoing paths
base_risk_availability = vector["Amazon Echo"][2]["base"]*availability[vector["Amazon Echo"][2]["availabilityImpact"]]
base_risk_integrity = vector["Amazon Echo"][2]["base"]*integrity[vector["Amazon Echo"][2]["integrityImpact"]]
base_risk_confidentiality = vector["Amazon Echo"][2]["base"]*confidentiality[vector["Amazon Echo"][2]["confidentialityImpact"]]

echo_one_exp = base_exploitability*behavioral_uptime["frequently_online"]*behavioral_ssl["not_encrypted"]
echo_one_imp = base_impact*behavioral_blacklisted_ip["not_accessed"]

print "Echo exploitability: ", math.tanh(echo_one_exp/100.0), "Echo impact: ", math.tanh(echo_one_imp/100.0), "Echo risk confidentiality: ", math.tanh(base_risk_confidentiality/100), "Echo risk integrity: ", math.tanh(base_risk_integrity/100), "Echo risk avalilability: ", math.tanh(base_risk_availability/100)
print "Network exploitability: ", math.tanh(echo_one_exp/100.0), "Network impact: ", math.tanh(echo_one_imp/100.0), "Network risk confidentiality: ", math.tanh(base_risk_confidentiality/100), "Network risk integrity: ", math.tanh(base_risk_integrity/100), "Network risk avalilability: ", math.tanh(base_risk_availability/100)

'''
One device, all CVEs
'''

base_exploitability += vector["Amazon Echo"][0]["exploitability"] + vector["Amazon Echo"][1]["exploitability"] # no incoming paths
base_impact += vector["Amazon Echo"][0]["impact"] + vector["Amazon Echo"][1]["impact"]# no outgoing paths
base_risk_availability += vector["Amazon Echo"][0]["base"]*availability[vector["Amazon Echo"][0]["availabilityImpact"]] + vector["Amazon Echo"][1]["base"]*availability[vector["Amazon Echo"][1]["availabilityImpact"]]
base_risk_integrity += vector["Amazon Echo"][0]["base"]*integrity[vector["Amazon Echo"][0]["integrityImpact"]] + vector["Amazon Echo"][1]["base"]*integrity[vector["Amazon Echo"][1]["integrityImpact"]]
base_risk_confidentiality += vector["Amazon Echo"][0]["base"]*confidentiality[vector["Amazon Echo"][0]["confidentialityImpact"]] + vector["Amazon Echo"][1]["base"]*confidentiality[vector["Amazon Echo"][1]["confidentialityImpact"]]

echo_all_exp = base_exploitability*behavioral_uptime["rarely_online"]*behavioral_ssl["not_encrypted"]
echo_all_imp = base_impact*behavioral_blacklisted_ip["not_accessed"]

print "Echo exploitability: ", math.tanh(echo_all_exp/100.0), "Echo impact: ", math.tanh(echo_all_imp/100.0), "Echo risk confidentiality: ", math.tanh(base_risk_confidentiality/100), "Echo risk integrity: ", math.tanh(base_risk_integrity/100), "Echo risk avalilability: ", math.tanh(base_risk_availability/100)
print "Network exploitability: ", math.tanh(echo_all_exp/100.0), "Network impact: ", math.tanh(echo_all_imp/100.0), "Network risk confidentiality: ", math.tanh(base_risk_confidentiality/100), "Network risk integrity: ", math.tanh(base_risk_integrity/100), "Network risk avalilability: ", math.tanh(base_risk_availability/100)

base_exploitability += (echo_non_cve_exp*.1*(vector["Amazon Echo"][0]["exploitability"] + vector["Amazon Echo"][1]["exploitability"] + vector["Belkin WeMo"][1]["exploitability"] + vector["Belkin WeMo"][2]["exploitability"]))
base_impact += (echo_non_cve_imp*.1*(vector["Amazon Echo"][0]["impact"] + vector["Amazon Echo"][1]["impact"] + vector["Belkin WeMo"][1]["impact"] + vector["Belkin WeMo"][2]["impact"]))
base_risk_availability += (echo_non_cve_bas*2*availability["LOW"]*.1*(vector["Amazon Echo"][0]["base"] + vector["Amazon Echo"][1]["base"] + vector["Belkin WeMo"][1]["base"] + vector["Belkin WeMo"][2]["base"]))
base_risk_integrity += (echo_non_cve_bas*2*integrity["LOW"]*.1*(vector["Amazon Echo"][0]["base"] + vector["Amazon Echo"][1]["base"] + vector["Belkin WeMo"][1]["base"] + vector["Belkin WeMo"][2]["base"]))
base_risk_confidentiality += (echo_non_cve_bas*2*confidentiality["LOW"]*.1*(vector["Amazon Echo"][0]["base"] + vector["Amazon Echo"][1]["base"] + vector["Belkin WeMo"][1]["base"] + vector["Belkin WeMo"][2]["base"]))

base_exploitability_d2 = vector["Belkin WeMo"][0]["exploitability"] + vector["Belkin WeMo"][1]["exploitability"] + vector["Belkin WeMo"][2]["exploitability"] + vector["Belkin WeMo"][3]["exploitability"] + vector["Belkin WeMo"][4]["exploitability"]
base_exploitability_d2 += vector["Belkin WeMo"][5]["exploitability"]*(.1*vector["Amazon Echo"][2]["exploitability"]) 
base_exploitability_d2 += wemo_non_cve_exp*.1*(vector["Belkin WeMo"][1]["exploitability"] + vector["Belkin WeMo"][2]["exploitability"])

base_impact_d2 = vector["Belkin WeMo"][0]["impact"] + vector["Belkin WeMo"][1]["impact"] + vector["Belkin WeMo"][2]["impact"] + vector["Belkin WeMo"][3]["impact"] + vector["Belkin WeMo"][4]["impact"]
base_impact_d2 += vector["Belkin WeMo"][5]["impact"]*(.1*vector["Amazon Echo"][2]["impact"]) 
base_impact_d2 += wemo_non_cve_imp*.1*(vector["Belkin WeMo"][1]["impact"] + vector["Belkin WeMo"][2]["impact"])

base_risk_availability_d2 = vector["Belkin WeMo"][0]["base"]*2*availability[vector["Belkin WeMo"][0]["availabilityImpact"]] + vector["Belkin WeMo"][1]["base"]*2*availability[vector["Belkin WeMo"][1]["availabilityImpact"]] + vector["Belkin WeMo"][2]["base"]*2*availability[vector["Belkin WeMo"][2]["availabilityImpact"]] + vector["Belkin WeMo"][3]["base"]*2*availability[vector["Belkin WeMo"][3]["availabilityImpact"]] + vector["Belkin WeMo"][4]["base"]*2*availability[vector["Belkin WeMo"][4]["availabilityImpact"]]
base_risk_integrity_d2 = vector["Belkin WeMo"][0]["base"]*2*integrity[vector["Belkin WeMo"][0]["integrityImpact"]] + vector["Belkin WeMo"][1]["base"]*2*integrity[vector["Belkin WeMo"][1]["integrityImpact"]] + vector["Belkin WeMo"][2]["base"]*2*integrity[vector["Belkin WeMo"][2]["integrityImpact"]] + vector["Belkin WeMo"][3]["base"]*2*integrity[vector["Belkin WeMo"][3]["integrityImpact"]] + vector["Belkin WeMo"][4]["base"]*2*integrity[vector["Belkin WeMo"][4]["integrityImpact"]]
base_risk_confidentiality_d2 = vector["Belkin WeMo"][0]["base"]*2*confidentiality[vector["Belkin WeMo"][0]["confidentialityImpact"]] + vector["Belkin WeMo"][1]["base"]*2*confidentiality[vector["Belkin WeMo"][1]["confidentialityImpact"]] + vector["Belkin WeMo"][2]["base"]*2*confidentiality[vector["Belkin WeMo"][2]["confidentialityImpact"]] + vector["Belkin WeMo"][3]["base"]*2*confidentiality[vector["Belkin WeMo"][3]["confidentialityImpact"]] + vector["Belkin WeMo"][4]["base"]*2*confidentiality[vector["Belkin WeMo"][4]["confidentialityImpact"]]


echo_both_exp = base_exploitability*behavioral_uptime["rarely_online"]*behavioral_ssl["not_encrypted"]
echo_both_imp = base_impact*behavioral_blacklisted_ip["not_accessed"]

wemo_both_exp = base_exploitability_d2*behavioral_uptime["frequently_online"]*behavioral_ssl["not_encrypted"]
wemo_both_imp = base_impact_d2*behavioral_blacklisted_ip["not_accessed"]

print "Echo exploitability: ", math.tanh(echo_both_exp/100.0), "Echo impact: ", math.tanh(echo_both_imp/100.0), "Echo risk confidentiality: ", math.tanh(base_risk_confidentiality/100), "Echo risk integrity: ", math.tanh(base_risk_integrity/100), "Echo risk avalilability: ", math.tanh(base_risk_availability/100)
print "WeMo exploitability: ", math.tanh(wemo_both_exp/100.0), "WeMo impact: ", math.tanh(wemo_both_imp/100.0), "WeMo risk confidentiality: ", math.tanh(base_risk_confidentiality_d2/100), "WeMo risk integrity: ", math.tanh(base_risk_integrity_d2/100), "WeMo risk avalilability: ", math.tanh(base_risk_availability_d2/100)
print "Network exploitability: ", math.tanh((echo_both_exp+wemo_both_exp)/100.0), "Network impact: ", math.tanh((echo_both_imp+wemo_both_imp)/100.0), "Network risk confidentiality: ", math.tanh((base_risk_confidentiality+base_risk_confidentiality_d2)/100), "Network risk integrity: ", math.tanh((base_risk_integrity+base_risk_integrity_d2)/100), "Network risk availability: ", math.tanh((base_risk_availability+base_risk_availability_d2)/100)