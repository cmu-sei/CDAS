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
1. python-stix
    (https://github.com/STIXProject/python-stix/blob/master/LICENSE.txt)
    Copyright 2017 Mitre Corporation.
2. numpy (https://numpy.org/doc/stable/license.html)
    Copyright 2005 Numpy Developers.
3. reportlab (https://bitbucket.org/rptlab/reportlab/src/default/LICENSE.txt)
    Copyright 2000-2018 ReportLab Inc.
4. drawSvg (https://github.com/cduck/drawSvg/blob/master/LICENSE.txt)
    Copyright 2017 Casey Duckering.
5. Cyber Threat Intelligence Repository (Mitre/CTI)
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

    def __init__(self, stix=None, actor_name_1=None, actor_name_2=None, countries_fs=None, fs=None, **kwargs):

        if len(kwargs) > 0:
            self.__dict__.update(kwargs)
        else:
            self.id = "intrusion-set--" + str(uuid.uuid4())

            # Create the name, but don't reuse names already taken
            actors = fs.query("SELECT name,aliases,attribution")
            names_taken = [ta[0] for ta in actors]
            adj = np.random.choice(actor_name_1)
            while adj in [name.split(' ')[0] for name in names_taken]:
                adj = np.random.choice(actor_name_1)
            noun = np.random.choice(actor_name_2)
            while noun in [name.split(' ')[1] for name in names_taken]:
                noun = np.random.choice(actor_name_2)
            self.name = adj + " " + noun

            self.sophistication = str(np.random.choice(stix['threat-actor-sophistication']))
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

            last_seen = date.fromordinal(np.random.randint(
                date.today().replace(year=date.today().year-1).toordinal(),
                date.today().toordinal()))
            while last_seen < self.first_seen:
                last_seen = date.fromordinal(np.random.randint(
                    date.today().replace(year=date.today().year-1).toordinal(),
                    date.today().toordinal()))
            self.last_seen = last_seen

            motivations = list(np.random.choice(
                stix['attack-motivation'], np.random.randint(2, 4), replace=False))
            self.primary_motivation = str(motivations[0])
            self.secondary_motivations = motivations[1:]
            self.goals = list(
                np.random.choice(stix['goals'], np.random.randint(2, 4), False))

            # Find countries most likely to host threat actors
            have_actors = [ta[2] for ta in actors]
            countries = countries_fs.query(
                "SELECT name,terrorism,international_disputes,percent_GDP_on_military")
            if self.actor_type == "terrorist":
                attr_countries = [
                    country[0] for country in countries
                    if country[1] is not None and
                    country[0] not in have_actors]
            elif self.actor_type == "nation-state":
                attr_countries = [
                    (country[0], country[3])
                    for country in countries
                    if country[2] is not None and
                    country[0] not in have_actors]
                attr_countries.sort(key=lambda x: x[1])
                attr_countries = [country[0] for country in attr_countries]
            else:
                attr_countries = [
                    country[0] for country in countries
                    if country[0] not in have_actors]
            if len(attr_countries) == 0:
                attr_countries = [
                    country[0] for country in countries
                    if country[0] not in have_actors]
                if len(attr_countries) == 0:
                    # all of the countries already have at least one actor
                    attr_countries = [country[0] for country in countries]
            # Set attribution
            self.attribution = attr_countries.pop()

    def _serialize(self):
        serialized = {}
        for key, value in self.__dict__.items():
            if isinstance(value, date):
                s_value = str(value)
            else:
                s_value = value
            serialized[key] = s_value
        return serialized

    def save(self, relationships, directory, filetype, tools_fs, malware_fs, events_fs, ttp_fs):
        """Saves the attributes of the Threat Actor to a specified file.

        Parameters
        ----------
        actor : stix2 ThreatActor object
            the threat actor to save
        directory : str
            Path to save output
        filetype : str
            For output file with country data (json or pdf)
        fs_gen : FileSystemStore  object
            Data store with info about threat actor
        fs_real : FileSystemSource object
            Data store with reference information about real world data
        """

        filename = directory + self.name.replace(' ', '')

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
            tool_names.append(tools_fs.query(f"SELECT name WHERE id='{t}'")[0][0])
        m_s = []
        for m in malwares:
            m_s.append(malware_fs.query(f"SELECT name WHERE id='{m}'")[0][0])

        if filetype == 'json':
            with open(filename+".json", 'w') as f:
                json.dump(self._serialize(), f)
            f.close()
        elif filetype == 'pdf':
            ss = getSampleStyleSheet()
            pdf = platy.SimpleDocTemplate(filename + ".pdf")
            flowables = []

            p = (
                f'{self.name} is a {self.actor_type} group also '
                f'known as {" or ".join(self.aliases)}. It was first seen in '
                f'{self.first_seen}, and is attributed to '
                f'the state of {self.attribution}. Its level of '
                f'sophistication is {self.sophistication}, and its '
                f'primary motivation is {self.primary_motivation}, though it '
                f'is sometimes motivated by '
                f'{" and ".join(self.secondary_motivations)}.'
            )
            flowables.append(platy.Paragraph(self.name, ss['Heading1']))
            flowables.append(platy.Paragraph(p, ss['BodyText']))

            p = self.name + "'s goals are "
            flowables.append(platy.Paragraph(p, ss['BodyText']))
            bullets = []
            for g in self.goals:
                p = platy.Paragraph(g, ss['Normal'])
                bullets.append(platy.ListItem(p, leftIndent=35))
            flowables.append(platy.ListFlowable(bullets, bulletType='bullet'))

            flowables.append(platy.Paragraph('Tools', ss['Heading2']))
            p = "This threat actor is known to use the following tools."
            flowables.append(platy.Paragraph(p, ss['BodyText']))

            bullets = []
            for tool in sorted(tool_names[:10], key=str.casefold):
                p = platy.Paragraph(tool, ss['Normal'])
                bullets.append(platy.ListItem(p, leftIndent=35))

            flowables.append(platy.ListFlowable(bullets, bulletType='bullet'))

            flowables.append(platy.Paragraph('Malware', ss['Heading2']))
            p = "This threat actor is known to use the following malware."
            flowables.append(platy.Paragraph(p, ss['BodyText']))

            bullets = []
            for malware in sorted(m_s[:5], key=str.casefold):
                p = platy.Paragraph(malware, ss['Normal'])
                bullets.append(platy.ListItem(p, leftIndent=35))
            flowables.append(platy.ListFlowable(bullets, bulletType='bullet'))

            flowables.append(
                platy.Paragraph('Attack Patterns', ss['Heading2']))
            for t in ttps:
                ttp = ttp_fs.get(t)
                p = f"{ttp.name}"
                flowables.append(platy.Paragraph(p, ss['Italic']))
                p = []
                for ref in ttp.references:
                    if ref['source_name'] == "mitre-attack":
                        p.append("Mitre Attack: "+ref['external_id'])
                    elif ref['source_name'] == "capec":
                        p.append(ref['external_id'])
                if len(p) > 0:
                    p = "(" + ", ".join(p) + ")\n"
                    flowables.append(platy.Paragraph(p, ss['BodyText']))
                else:
                    try:
                        flowables.append(platy.Paragraph(
                            ttp.description+'\n', ss['BodyText']))
                    except AttributeError:
                        pass
                flowables.append(platy.Paragraph("", ss['Heading2']))

            flowables.append(
                platy.Paragraph('Related Reporting', ss['Heading2']))
            p = f"These reported incidents are likely or highly likely to be \
                attributed to {self.name}, though there may be others:"
            flowables.append(platy.Paragraph(p, ss['BodyText']))
            sightings = events_fs.query(f"SELECT first_seen WHERE sighting_of_ref='{self.id}'")
            r_nums = [s[0] for s in sightings][:15]
            bullets = []
            for r in sorted(r_nums):
                p = platy.Paragraph(
                    r.replace(' ', '_').replace(':', '')[:15], ss['Normal'])
                bullets.append(platy.ListItem(p, leftIndent=35))
            flowables.append(platy.ListFlowable(bullets, bulletType='bullet'))

            pdf.build(flowables)
        elif filetype == 'html':
            filename += ".json"
            f = open(filename, 'w')
            f.write("var data = " + str(actor_dict))
            f.close()
        else:
            raise NotImplementedError(
                f"Output file type, {filetype}, not supported")


class Organization():

    orgCount = -1  # track the number of orgs created starting at 0
    
    def __init__(self, stix=None, country=None, org_names=None, assessment=None, **kwargs):

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