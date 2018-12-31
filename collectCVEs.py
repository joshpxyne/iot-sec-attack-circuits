import json

dev_map = {}
with open('devicemap.json') as device_json:
    devices = json.load(device_json)
    for device in devices:
        dev_map[device["device"]] = []
        for cve_id in device["CVE_IDs"]:
            with open("cve-data/"+str(cve_id[4:8]+'.json')) as cve_json:
                cve_data = json.load(cve_json)
                for cve in cve_data["CVE_Items"]:
                    if cve["cve"]["CVE_data_meta"]["ID"]==cve_id:
                        dev_map[device["device"]].append(cve)
                        print(cve)
    print dev_map
# now write output to a file
descfile = open("known_cves.json", "w")
# magic happens here to make it pretty-printed
descfile.write(json.dumps(dev_map, indent=4, sort_keys=True))
descfile.close()