'''
Cybersecurity Decision Analysis Simulator (CDAS)

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE
MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO
WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING,
BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, 
EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON 
UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM 
PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or contact 
permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release 
and unlimited distribution.  Please see Copyright notice for non-US Government 
use and distribution.

Carnegie Mellon® and CERT® are registered in the U.S. Patent and Trademark 
Office by Carnegie Mellon University.

This Software includes and/or makes use of the following Third-Party Software 
subject to its own license:
1. python-stix (https://github.com/STIXProject/python-stix/blob/master/LICENSE.txt) 
    Copyright 2017 Mitre Corporation.
2. numpy (https://numpy.org/doc/stable/license.html) 
    Copyright 2005 Numpy Developers.
3. reportlab (https://bitbucket.org/rptlab/reportlab/src/default/LICENSE.txt) 
    Copyright 2000-2018 ReportLab Inc.
4. drawSvg (https://github.com/cduck/drawSvg/blob/master/LICENSE.txt) 
    Copyright 2017 Casey Duckering.

DM20-0573
'''

import json
import numpy as np
import string
from datetime import datetime, timedelta
import reportlab.platypus as platy
from reportlab.lib.styles import getSampleStyleSheet
from stix2 import FileSystemStore, FileSystemSource, Filter
from stix2.v21 import Sighting, Relationship

def random_indicator(itype):
    if itype == 'IPv4 address':
        ipv4 = [str(quad) for quad in np.random.randint(0,255,4)]
        indicator = ".".join(ipv4)
    elif itype == 'domain name':
        generic_tlds = ['.com','.net','.org','.site','.biz']
        name = np.random.choice(list(string.ascii_letters+string.digits),10)
        indicator = ''.join(name) + np.random.choice(generic_tlds)
    else:
        print(f"ERROR: {itype} is not an available type for random_indicator")
    return indicator

def simulate(actors,orgs,tools,malwares,fs,start_date,td):

    # Reference to convert the agent's sophistication level to an integer
    skill_levels = {
        "minimal":1,
        "intermediate":2,
        "advanced":3,
        "expert":4,
        "innovator": 5,
        "strategic": 6
    }

    for agent in actors:
        # Pick a random target  @TODO - make this more logical later
        target_id = np.random.choice([org.id for org in orgs])
        target = [org for org in orgs if org['id'] == target_id][0]
      
        success = np.random.choice([True, False])
        tool = np.random.choice(tools)
        tool_rels = fs.query([Filter('type','=','relationship'),
            Filter('source_ref','=',agent.id),
            Filter('target_ref','=',tool.id)])
        if len(tool_rels) == 0:
            fs.add(Relationship(agent,'uses',tool))
        indicator_type = np.random.choice(['IPv4 address','domain name'])
        used_malware = np.random.choice(['yes', 'no'], p=[.25, .75])
        if used_malware == 'yes':
            malware = np.random.choice(malwares)
            mw_rels = fs.query([Filter('type','=','relationship'),
                Filter('source_ref','=',agent.id),
                Filter('target_ref','=',malware.id)])
            if len(mw_rels) == 0:
                fs.add(Relationship(agent,'uses',malware))
        target_description = json.loads(target.description)
        if success == True:
            description = (
                f'On {str(start_date)[:10]}, an attacker successfully attacked'
                f' COMPANY located in the country of '
                f'{target_description["Background"]["headquarters"]} to '
                f'{np.random.choice(agent.goals)}. The tool, {tool.name}, was '
                f'used during the course of the attack, and one of the '
                f'indicators discovered was the {indicator_type}, '
                f'{random_indicator(indicator_type)}.')
        else:
            description = (
                f'On {str(start_date)[:10]}, an attack was attempted against '
                f'COMPANY located in the country of '
                f'{target_description["Background"]["headquarters"]}. The '
                f'attacker used the tool, {tool.name}, during its attack. It '
                f'is believed the attack was an unsuccessful attempt to '
                f'{np.random.choice(agent.goals)}, and one of the indicators '
                f'discovered was the {indicator_type}, '
                f'{random_indicator(indicator_type)}.')
        if used_malware == 'yes':
            description += (
                f' The attacker also attempted to use the malware '
                f'{malware.name}.')
        sighting_of_ref = agent.id

        fs.add(Sighting(
            description = description,
            first_seen = start_date,
            sighting_of_ref = sighting_of_ref))
        start_date += timedelta(td)

# @TODO add "defense" option back in as closure of vulnerabilities

def save(e,agent_store,vuln_store,filename):
    
    ss = getSampleStyleSheet()
    flowables = []
    r_num = str(e.first_seen).replace('-','').replace(' ','_').replace(':','')
    flowables.append(platy.Paragraph(f"Report #{r_num[:15]}", ss['Heading1']))
    flowables.append(platy.Paragraph("Date:",ss['Italic']))
    flowables.append(platy.Paragraph(str(e.first_seen)[:19],ss['BodyText']))
    flowables.append(platy.Paragraph("Description:",ss['Italic']))
    flowables.append(platy.Paragraph(e.description,ss['BodyText']))
    if 'vulnerability' in e.sighting_of_ref:
        p = "References:"
        vuln = vuln_store.query(Filter("id", "=", e.sighting_of_ref))[0]
        p2 = vuln.name + ": " + vuln.description
    else: 
        p = "Possible attribution:"
        p2 = agent_store.query(Filter("id", "=", e.sighting_of_ref))[0].name
    flowables.append(platy.Paragraph(p,ss['Italic']))
    flowables.append(platy.Paragraph(p2,ss['BodyText']))
    pdf = platy.SimpleDocTemplate(filename+r_num[:15]+'.pdf')
    pdf.build(flowables)