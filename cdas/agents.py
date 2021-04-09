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
    _pdf_headers = {
        'Description': {
            'description': '', 'modified': 'Data last modified',
            'first-seen': 'First seen',
            'sophistication': 'Sophistication', 'actor_type': 'Actor type',
            'aliases': 'Aliases', 'sectors': 'Targeted sectors', 
            'target_locations': 'Targeted locations',
            'primary_motivation': 'Primary motivation',
            'secondary_motivations': 'Secondary motivations',
            'goals': 'Goals', 'attribution': 'Attributed to the country of'},
        'Technical Appendix': {
            'tools': 'This actor has been known to use the following tools',
            'malware': 'Malware', 'ttps':'TTPs'
        },
        'References': {
            'external_references': ''
        }
    }

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
                list(stix['threat-actor-sophistication'])))
            self.actor_type = np.random.choice(
                list(stix["threat-actor-type"].keys()),
                p=list(stix["threat-actor-type"].values()))

            # target sectors
            self.sectors = list(np.random.choice(
                stix['sectors'], np.random.randint(2, 4), False))

            aliases = [f"APT {1000+(len(actors))}"]
            aliases_taken = [ta[1] for ta in actors]
            alias = (
                f"{np.random.choice(stix['alias 1'])} "
                f"{np.random.choice(stix['alias 2'])}")
            while alias in aliases_taken:
                alias = (
                    f'{np.random.choice(stix["alias 1"])} '
                    f'{np.random.choice(stix["alias 2"])}')
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

        num_mal = sophistication[self.sophistication] - 1

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
                s_value = value.strftime("%d %b %Y")
            else:
                s_value = value
            serialized[key] = s_value
        return serialized

    def _mispizer(self):
        """
        Formats the Threat Actor attributes in dictionary format for MISP
        """

        cluster = {"GalaxyCluster": {
            "uuid": self.id[15:],
            "collection_uuid": "86fa35a5-69e3-429e-8325-9a55f6e2f889",
            "type": "threat-actor",
            "value": self.name,
            "tag_name": f"misp-galaxy:threat-actor=\"{self.id[15:]}\"",
            "description": self.name,
            "source": "CDAS",
            "authors": [
                "CDAS"
            ],
            "version": "1",
            "distribution": "0",
            "sharing_group_id": None,
            "default": False,
            "locked": False,
            "published": False,
            "deleted": False,
            "Galaxy": {
                "uuid": "86fa35a5-69e3-429e-8325-9a55f6e2f889",
                "name": "Threat Actor", "type": "threat-actor",
                "description":  "Threat actor information provided by CDAS",
                "version": "1", "icon": "user-secret", "namespace": "cdas"
            },
            "GalaxyClusterRelation": [],
            "Org": {
                "name": "CDAS",
                "description": "Cybersecurity Decision Analysis Simulator",
                "type": "Simulation generator",
                "nationality": "Not specified",
                "uuid": "4b1e8e88-78fb-48bd-8a46-5de63fd16688",
                "contacts": "",
                "local": False,
                "restricted_to_domain": "",
                "landingpage": None
                },
                "Orgc": {
                    "name": "CDAS",
                    "description": "Cybersecurity Decision Analysis Simulator",
                    "type": "Simulation generator",
                    "nationality": "Not specified",
                    "uuid": "4b1e8e88-78fb-48bd-8a46-5de63fd16688",
                    "local": False,
                    "restricted_to_domain": "",
                    "landingpage": None
                },
            }
        }

        serialized = []
        for key, value in self.__dict__.items():
            if key == 'id':
                continue
            element = {"key":key}
            if isinstance(value, date):
                element["value"] = value.strftime("%d %b %Y")
            elif isinstance(value, list):
                element["value"] = ", ".join(value)
            else:
                element["value"] = value
            serialized.append(element)
        cluster['GalaxyCluster']['GalaxyElement'] = serialized
        return cluster

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
            q = f"SELECT name,external_references WHERE id='{t}'"
            t_name, refs = ttp_fs.query(q)[0]
            for ref in refs:
                if ref['source_name'].startswith("mitre"):
                    t_name += " (Mitre Attack: "+ref['external_id']+ ')'
            ttp_names.append(t_name)
        if len(ttp_names) > 0:
            apt_to_save.ttps = ttp_names
        
        return apt_to_save


class Defender():
    """Describes a defending organization

    Args:
        sectors (list): economic sectors to chose from
        country (str): names of countries to chose from
        org_names (list): names to chose from
        assessment (dict): used for vulnerability status 
        **kwargs: Used to instantiate a Defender from the given values

    Attributes:
        _file_specification (dict): requirements for a defender input file
        id (str): unique ID starting with "defender--"
        name (str): name of the defending organization
    """

    _file_specification = {
        "ext": "json",
        "prefix": "defender--",
        "req_attrs": ['id', 'name']}
    _pdf_headers = {
        'Company Description': {
            'background': '', 'revenue': 'Annual revenue', 'sector': 'Sector',
            'headquarters': 'Headquartered in the country of',
            'number_of_employees': 'Number of employees'},
        'Vulnerability Assessment': {
            'vulnerability_score': 'Score (out of 100)',
            'vulns': 'Vulnerabilities found'}
    }
    
    def __init__(self, sectors=None, country=None, org_names=None,
            assessment=None, **kwargs):

        if len(kwargs) > 0:
            self.__dict__.update(kwargs)
        else:
            self.id = "defender--" + str(uuid.uuid4())
            self.name = np.random.choice(org_names).strip()
            revenue = int(np.random.chisquare(1) * 10000)
            while revenue == 0:
                revenue = int(np.random.chisquare(1) * 10000)
            self.revenue = "$"+"{:,}".format(revenue)+" million"
            self.sector = np.random.choice(sectors)
            self.background = ""
            self.headquarters = country
            self.number_of_employees = "{:,}".format(np.random.randint(500, 15000))

            score = 0
            vulns = []
            dist = np.random.beta(3, 2)  # overall scoring distribution
            while dist < 0.2:
                dist = np.random.beta(3, 2)
            for cat in assessment:
                for r in assessment[cat]:
                    pf = np.random.choice(a=['Yes', 'No'], p=[dist, 1-dist])
                    if pf == 'Yes':
                        score += r['Value']
                    else:
                        vulns.append(f"({r['Requirement']}) {r['Description']}")
            self.vulnerability_score = int(score/313 * 100)
            self.vulns = vulns

    def _serialize(self):
        """
        Return the Defender attributes in a dictionary format with
        serializable values
        """
        serialized = {}
        for key, value in self.__dict__.items():
            serialized[key] = value
        return serialized

    def _mispizer(self):
        """
        Formats the Defender attributes in dictionary format for MISP
        """

        cluster = {"GalaxyCluster": {
            "uuid": self.id[10:],
            "collection_uuid": "c3609c3a-d0f9-4e7e-9566-3dab932e81bb",
            "type": "organization",
            "value": self.name,
            "tag_name": f"misp-galaxy:organization=\"{self.id[10:]}\"",
            "description": self.name,
            "source": "CDAS",
            "authors": [
                "CDAS"
            ],
            "version": "1",
            "distribution": "0",
            "sharing_group_id": None,
            "default": False,
            "locked": False,
            "published": False,
            "deleted": False,
            "Galaxy": {
                "uuid": "c3609c3a-d0f9-4e7e-9566-3dab932e81bb",
                "name": "Organization", "type": "organization",
                "description":  "Organization information provided by CDAS",
                "version": "1", "icon": "building", "namespace": "cdas"
            },
            "GalaxyClusterRelation": [],
            "Org": {
                "name": "CDAS",
                "description": "Cybersecurity Decision Analysis Simulator",
                "type": "Simulation generator",
                "nationality": "Not specified",
                "uuid": "4b1e8e88-78fb-48bd-8a46-5de63fd16688",
                "contacts": "",
                "local": False,
                "restricted_to_domain": "",
                "landingpage": None
                },
                "Orgc": {
                    "name": "CDAS",
                    "description": "Cybersecurity Decision Analysis Simulator",
                    "type": "Simulation generator",
                    "nationality": "Not specified",
                    "uuid": "4b1e8e88-78fb-48bd-8a46-5de63fd16688",
                    "local": False,
                    "restricted_to_domain": "",
                    "landingpage": None
                },
            }
        }

        serialized = []
        for key, value in self.__dict__.items():
            if key == 'id':
                continue
            element = {"key":key}
            if isinstance(value, list):
                element["value"] = '; '.join(value)
            else:
                element["value"] = str(value)
            serialized.append(element)
        cluster['GalaxyCluster']['GalaxyElement'] = serialized
        return cluster