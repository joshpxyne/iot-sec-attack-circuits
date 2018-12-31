import json

dev_map = {}
with open('devicemap.json') as device_json:
    devices = json.load(device_json)
    with open("known_cves.json") as cve_json:
        cve_data = json.load(cve_json)
        for device in devices:
            dev_map[device["device"]] = []
            ind = 0
            for cve in cve_data[device["device"]]:
                dev_map[device["device"]].append({"description":cve["cve"]["description"]["description_data"][0]["value"], "inputs/outputs":[], "id": device["CVE_IDs"][ind]})
                ind+=1
                print(cve["cve"]["description"]["description_data"][0]["value"])
    print dev_map
descfile = open("descriptions.json", "w")
descfile.write(json.dumps(dev_map, indent=4, sort_keys=True))
descfile.close()