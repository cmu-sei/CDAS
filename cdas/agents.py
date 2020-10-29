'''
Cybersecurity Decision Analysis Simulator (CDAS)

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE
MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO
WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER
INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR
MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL.
CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT
TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or contact
permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release
and unlimited distribution.  Please see Copyright notice for non-US Government
use and distribution.

Carnegie Mellon® and CERT® are registered in the U.S. Patent and Trademark
Office by Carnegie Mellon University.

This Software includes and/or makes use of the following Third-Party Software
subject to its own license:
1. numpy (https://numpy.org/doc/stable/license.html)
    Copyright 2005 Numpy Developers.
2. reportlab (https://bitbucket.org/rptlab/reportlab/src/default/LICENSE.txt)
    Copyright 2000-2018 ReportLab Inc.
3. drawSvg (https://github.com/cduck/drawSvg/blob/master/LICENSE.txt)
    Copyright 2017 Casey Duckering.
4. Cyber Threat Intelligence Repository (Mitre/CTI)
    (https://github.com/mitre/cti/blob/master/LICENSE.txt)
    Copyright 2017 Mitre Corporation.

DM20-0573
'''

import weakref
import numpy as np
import json
from datetime import date, datetime
import uuid
import reportlab.platypus as platy
from reportlab.lib.styles import getSampleStyleSheet


class ThreatActor():
    """
    Advanced Persistent Threat Actor

    Args:
        stix (dict): Vocabulary set (seed words) used in creation of random
            actors. Optional if providing actor attributes via kwargs.
        actor_name_1 (list): List of words for the first word of the actor's
            name. Used for creating random actors; optional if providing actor
            attributes via kwargs.
        actor_name_2 (list): List of words for the second word of the actor's
            name. Used for creating random actors; optional if providing actor
            attributes via kwargs.
        countries_fs (FileStore object): Where the country data is stored.
        threat_actor_fs (FileStore object): Where the threat actor data is 
            stored.
        **kwargs: Used to instantiate an actor
    
    Attributes:
        _file_specification (dict): requirements for a threat actor input file
        id (str): unique ID starting with "intrusion-set--"
        name (str): Primary name of the APT
    """

    _file_specification = {
        "ext": "json",
        "prefix": "intrusion-set--",
        "req_attrs": ['id', 'name']}

    def __init__(self, stix=None, actor_name_1=None, actor_name_2=None, 
            countries_fs=None, threat_actor_fs=None, **kwargs):

        if len(kwargs) > 0:
            # We were given the data. Load it.
            self.__dict__.update(kwargs)
        else:
            # We were not given data. Make it up.
            self.id = "intrusion-set--" + str(uuid.uuid4())

            # Create the name, but don't reuse names already taken
            actors = threat_actor_fs.query("SELECT name,aliases,attribution")
            names_taken = [ta[0] for ta in actors]
            adj = np.random.choice(actor_name_1)
            while adj in [name.split(' ')[0] for name in names_taken]:
                adj = np.random.choice(actor_name_1)
            noun = np.random.choice(actor_name_2)
            while noun in [name.split(' ')[1] for name in names_taken]:
                noun = np.random.choice(actor_name_2)
            self.name = adj + " " + noun

            self.sophistication = str(np.random.choice(
                stix['threat-actor-sophistication']))
            self.actor_type = np.random.choice(
                list(stix["threat-actor-type"].keys()),
                p=list(stix["threat-actor-type"].values()))

            # target sectors
            self.sectors = list(np.random.choice(
                stix['sectors'], np.random.randint(2, 4), False))

            aliases = [f"APT {1000+(len(actors))}"]
            aliases_taken = [ta[1] for ta in actors]
            alias = (
                f"{np.random.choice(stix['colors'])} "
                f"{np.random.choice(stix['animals'])}")
            while alias in aliases_taken:
                alias = (
                    f'{np.random.choice(stix["colors"])} '
                    f'{np.random.choice(stix["animals"])}')
            aliases.append(alias)
            self.aliases = aliases

            self.first_seen = date.fromordinal(np.random.randint(
                date.today().replace(year=date.today().year-10).toordinal(),
                date.today().toordinal()))

            motivations = list(np.random.choice(
                stix['attack-motivation'], np.random.randint(2, 4), replace=False))
            self.primary_motivation = str(motivations[0])
            self.secondary_motivations = motivations[1:]
            self.goals = list(
                np.random.choice(stix['goals'], np.random.randint(2, 4), False))

            countries = countries_fs.query("SELECT name")
            # Set attribution
            self.attribution = np.random.choice([c[0] for c in countries])

    def create_fake_history(
            self, relationships, tools, malwares, ttps, sophistication):
        """Adds tools, malware, and TTPs for this APT to the relationship file.

        Args:
            relationships (dict): map APT to an object
            tools (list): all available tools (by id)
            malwares (list): all available malware (by id)
            ttps (list): all available TTPs (by id)
        """

        num_mal = sophistication.index(self.sophistication)

        some_tools = np.random.choice(tools, num_mal+2, False)
        for tool in some_tools:
            if (self.id,'uses',tool.id) not in relationships:
                relationships.append((self.id, 'uses', tool.id))

        some_malwares = np.random.choice(malwares, num_mal, False)
        for malware in some_malwares:
            if (self.id, 'uses', malware.id) not in relationships:
                relationships.append((self.id, 'uses', malware.id))

        some_ttps = np.random.choice(ttps, (num_mal+1)*2, False)
        for ttp in some_ttps:
            if (self.id,'uses',ttp.id) not in relationships:
                relationships.append((self.id, 'uses', ttp.id))

    def _serialize(self):
        """
        Return the Threat Actor attributes in a dictionary format with
        serializable values
        """
        serialized = {}
        for key, value in self.__dict__.items():
            if isinstance(value, date):
                s_value = str(value)
            else:
                s_value = value
            serialized[key] = s_value
        return serialized

    def _save(self, relationships, tools_fs, malware_fs, ttp_fs):
        """
        Fetches information about APT relationships to include in file output

        Args:
            relationships (dict): for looking up relationships to APT
            tools_fs (FileStore): for looking up tool names
            malware_fs (FileStore): for looking up malware names
            ttp_fs (FileStore): for looking up TTP descriptions

        Returns:
            ThreatActor object: with attributes for output
        """

        # We don't want to output all attributes of self exactly as is, so we
        # will copy self to another variable, apt_to_save, and manipulate that
        apt_to_save = self

        ttps, tools, malwares = [], [], []
        for r in relationships:
            if self.id == r[0] and "attack-pattern" in r[2]:
                ttps.append(r[2])
            elif self.id == r[0] and "tool" in r[2]:
                tools.append(r[2])
            elif self.id == r[0] and "malware" in r[2]:
                malwares.append(r[2])

        tool_names = []
        for t in tools:
            tool_names.append(
                tools_fs.query(f"SELECT name WHERE id='{t}'")[0][0])
        if len(tool_names) > 0:
            apt_to_save.tools = tool_names

        malware_names = []
        for m in malwares:
            malware_names.append(
                malware_fs.query(f"SELECT name WHERE id='{m}'")[0][0])
        if len(tool_names) > 0:
            apt_to_save.malware = malware_names

        ttp_names = []
        for t in ttps:
            t_name, refs = ttp_fs.query(f"SELECT name,references WHERE id='{t}'")[0]
            for ref in refs:
                if ref['source_name'].startswith("mitre"):
                    t_name += " (Mitre Attack: "+ref['external_id']+ ')'
            ttp_names.append(t_name)
        if len(ttp_names) > 0:
            apt_to_save.ttps = ttp_names
        
        return apt_to_save


class Organization():

    orgCount = -1  # track the number of orgs created starting at 0
    
    def __init__(self, stix=None, country=None, org_names=None,
            assessment=None, **kwargs):

        Organization.orgCount += 1

        if len(kwargs) > 0:
            self.__dict__.update(kwargs)
        else:
            self.id = 'organization--' + str(Organization.orgCount)
            self.name = np.random.choice(org_names).strip()
            revenue = int(np.random.chisquare(1) * 10000)
            while revenue == 0:
                revenue = int(np.random.chisquare(1) * 10000)
            self.revenue = "$"+"{:,}".format(revenue)+" million"
            self.sector = np.random.choice(stix['sectors'])
            self.background = "TODO"
            self.headquarters = country
            self.number_of_employees = "{:,}".format(np.random.randint(500, 15000))
            self.network_size = np.random.randint(1, 100)

            score = 0
            vulns = []
            dist = np.random.beta(2, 2)  # overall scoring distribution
            while dist == 0:
                dist = np.random.beta(2, 2)
            for cat in assessment:
                for r in assessment[cat]:
                    pf = np.random.choice(a=['Yes', 'No'], p=[dist, 1-dist])
                    if pf == 'Yes':
                        score += r['Value']
                    else:
                        vulns.append(r['Requirement'])
            self.vulnerability_score = int(score/313 * 100)
            self.vulns = vulns

    def _serialize(self):
        serialized = {}
        for key, value in self.__dict__.items():
            serialized[key] = value
        return serialized

def save_org(org, directory, filetype, assessment):
    """
    Saves information about the organization to a file.

    Paramters
    ---------
    org : stix2 Identity object
        the organization to save
    directory : str
        Path to save output
    filetype : str
        Type of output file (json or pdf)
    assessment : dictionary
        representation of NIST 800-171 assessment table
    """

    filename = directory + org.name.replace(' ', '')

    if filetype == 'json':
        with open(filename+".json", 'w') as f:
            json.dump(org._serialize(), f)
        f.close()
    elif filetype == 'pdf':
        ss = getSampleStyleSheet()
        pdf = platy.SimpleDocTemplate(filename + ".pdf")
        flowables = []
        flowables.append(platy.Paragraph(org.name, ss['Heading1']))
        p = f'Sector: {org.sector}'
        flowables.append(platy.Paragraph(p, ss['BodyText']))
        flowables.append(platy.Paragraph("Background", ss['Heading2']))
        p = (
            f'{org.name} is headquartered in the country of {org.headquarters}'
            f'. It has {org.number_of_employees} employees and an'
            f' annual revenue of {org.revenue}.'
        )
        flowables.append(platy.Paragraph(p, ss['BodyText']))
        flowables.append(platy.Paragraph("Computer Network", ss['Heading2']))
        p = f"Network size: {org.network_size} (on a scale of 100)"
        flowables.append(platy.Paragraph(p, ss['BodyText']))
        p = "NIST 800-171 Security Evaluation Results"
        flowables.append(platy.Paragraph(p, ss['Heading2']))
        p = f"Score: {org.vulnerability_score}/100"
        flowables.append(platy.Paragraph(p, ss['BodyText']))
        p = "Vulnerabilities (failed requirements):"
        flowables.append(platy.Paragraph(p, ss['BodyText']))
        bullets = []
        nist_reqs = {}
        for cat in assessment:
            for req in assessment[cat]:
                nist_reqs[req["Requirement"]] = req["Description"]
        for vuln in org.vulns:
            p = platy.Paragraph(f'({vuln}) {nist_reqs[vuln]}', ss['Normal'])
            bullets.append(platy.ListItem(p, leftIndent=35))
        flowables.append(platy.ListFlowable(bullets, bulletType='bullet'))
        pdf.build(flowables)
    elif filetype == 'html':
        filename += ".json"
        f = open(filename, 'w')
        f.write("var data = " + str(org_dict))
        f.close()
    else:
        raise NotImplementedError(
            f"Output file type, {filetype}, not supported")