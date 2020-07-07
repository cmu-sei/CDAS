import json
import os

with open('geopol_data.json') as f:
    geodata = json.load(f)
f.close()

resources = []
for r in geodata['resources']: resources.extend(geodata['resources'][r])
r = set(resources)

g = set(geodata['eximports'])

agriculture = []
for a in geodata['agriculture']: agriculture.extend(geodata['agriculture'][a])
a = set(agriculture)

print(sorted(r.intersection(g)))

'''
values = {'country':0,'not country':0}
for fn in os.listdir('cia_world_factbook'):
    with open('cia_world_factbook/'+fn) as f:
        country = json.load(f)
    f.close()

    if "Unknown" not in country['pipelines']:
        p_total = 0
        for p in country['pipelines']:
            p_total += int(p[:p.find('km')-1].replace(',',''))
        print(country['total_area'][:-5].replace(',',''),p_total)
'''