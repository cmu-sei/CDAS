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
from datetime import date
import uuid
import reportlab.platypus as platy
from reportlab.lib.styles import getSampleStyleSheet
from stix2.v21 import Relationship, Identity
from stix2 import Filter


class ThreatActor():

    def __init__(self, stix=None, actor_name_1=None, actor_name_2=None, countries_fs=None, fs=None, **kwargs):

        if len(kwargs) > 0:
            self.__dict__.update(kwargs)
        else:
            self.id = str(uuid.uuid4())

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

def save(actor, directory, filetype, fs_gen, fs_real):
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

    filename = directory + actor.name.replace(' ', '')

    relationships = fs_gen.query([
        Filter("type", "=", "relationship"),
        Filter("source_ref", "=", actor.id)])
    ttps, tools, malwares = [], [], []
    for r in relationships:
        if "attack-pattern" in r.target_ref:
            ttps.append(r.target_ref)
        elif "tool" in r.target_ref:
            tools.append(r.target_ref)
        elif "malware" in r.target_ref:
            malwares.append(r.target_ref)
        elif "location" in r.target_ref:
            countries = fs_gen.query([
                Filter("type", "=", "location"),
                Filter("id", "=", r.target_ref)])
    tool_names = [fs_real.query([
        Filter("type", "=", "tool"), Filter("id", "=", t)])[0].name
        for t in tools]
    m_s = [fs_real.query([
        Filter("type", "=", "malware"), Filter("id", "=", m)])[0].name
        for m in malwares]
    actor_dict = {
        "name": actor.name,
        "aliases": actor.aliases,
        "first_seen": actor.first_seen.strftime("%B %Y"),
        "last_seen": actor.last_seen.strftime("%B %Y"),
        "attribution": countries[0].name,
        "resource_level": actor.resource_level,
        "primary motivation": actor.primary_motivation,
        "secondary motivations": actor.secondary_motivations,
        "description": actor.description,
        "ttps": ttps,
        "tools": tool_names,
        "malware": m_s
    }

    if filetype == 'json':
        with open(filename+".json", 'w') as f:
            json.dump(actor_dict, f)
        f.close()
    elif filetype == 'pdf':
        ss = getSampleStyleSheet()
        pdf = platy.SimpleDocTemplate(filename + ".pdf")
        flowables = []

        try:
            actor_dict = json.loads(actor.description)
            p = (
                f'{actor.name} is a {actor_dict["actor_type"]} group also '
                f'known as {" or ".join(actor.aliases)}. It was first seen in '
                f'{actor.first_seen.strftime("%B %Y")}, and is attributed to '
                f'the state of {countries[0].name}. Its level of '
                f'sophistication is {actor_dict["sophistication"]}, and its '
                f'primary motivation is {actor.primary_motivation}, though it '
                f'is sometimes motivated by '
                f'{" and ".join(actor.secondary_motivations)}.'
            )
        except json.decoder.JSONDecodeError:
            actor_dict = None
            p = actor.description
        flowables.append(platy.Paragraph(actor.name, ss['Heading1']))
        flowables.append(platy.Paragraph(p, ss['BodyText']))

        if actor_dict is not None:
            p = actor.name + "'s goals are "
            flowables.append(platy.Paragraph(p, ss['BodyText']))
            bullets = []
            for g in actor.goals:
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
            ttp = fs_real.query([
                Filter("type", "=", "attack-pattern"),
                Filter("id", "=", t)])[0]
            p = f"{ttp.name}"
            flowables.append(platy.Paragraph(p, ss['Italic']))
            p = []
            for ref in ttp.external_references:
                if ref.source_name == "mitre-attack":
                    p.append("Mitre Attack: "+ref.external_id)
                elif ref.source_name == "capec":
                    p.append(ref.external_id)
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
            attributed to {actor.name}, though there may be others:"
        flowables.append(platy.Paragraph(p, ss['BodyText']))
        sightings = fs_gen.query([
            Filter("type", "=", "sighting"),
            Filter("sighting_of_ref", "=", actor.id)])
        r_nums = [
            str(s.first_seen).replace('-', '') for s in sightings][:15]
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
    
    def __init__(self, stix=None, country=None, org_names=None, assessment=None, **kwargs):

        if len(kwargs) > 0:
            self.__dict__.update(kwargs)
        else:
            self.name = np.random.choice(org_names)
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
    org_desc = json.loads(org.description)
    org_dict = {
        "name": org.name,
        "background": org_desc['Background'],
        "network_size": org_desc['Network']['size'],
        "vulnerability_level": org_desc['Security Posture']['vulnerability'],
        "NIST vulnerabilities": org_desc['Security Posture']['vulns'],
        "sectors": org.sectors
    }

    if filetype == 'json':
        with open(filename+".json", 'w') as f:
            json.dump(org_dict, f)
        f.close()
    elif filetype == 'pdf':
        ss = getSampleStyleSheet()
        pdf = platy.SimpleDocTemplate(filename + ".pdf")
        flowables = []
        flowables.append(platy.Paragraph(org.name, ss['Heading1']))
        p = f'Sector: {", ".join(org.sectors)}'
        flowables.append(platy.Paragraph(p, ss['BodyText']))
        flowables.append(platy.Paragraph("Background", ss['Heading2']))
        p = (
            f'{org.name} is headquartered in the country of '
            f'{org_desc["Background"]["headquarters"]}. It has '
            f'{org_desc["Background"]["number of employees"]} employees and an'
            f' annual revenue of {org_desc["Background"]["annual revenue"]}.'
        )
        flowables.append(platy.Paragraph(p, ss['BodyText']))
        flowables.append(platy.Paragraph("Computer Network", ss['Heading2']))
        p = f"Network size: {org_desc['Network']['size']} (on a scale of 100)"
        flowables.append(platy.Paragraph(p, ss['BodyText']))
        p = "NIST 800-171 Security Evaluation Results"
        flowables.append(platy.Paragraph(p, ss['Heading2']))
        p = f"Score: {org_desc['Security Posture']['vulnerability']}/100"
        flowables.append(platy.Paragraph(p, ss['BodyText']))
        p = "Vulnerabilities (failed requirements):"
        flowables.append(platy.Paragraph(p, ss['BodyText']))
        bullets = []
        nist_reqs = {}
        for cat in assessment:
            for req in assessment[cat]:
                nist_reqs[req["Requirement"]] = req["Description"]
        for vuln in org_desc['Security Posture']['vulns']:
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