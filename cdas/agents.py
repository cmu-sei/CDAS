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
import reportlab.platypus as platy
from reportlab.lib.styles import getSampleStyleSheet
from stix2.v21 import Relationship, ThreatActor, Identity
from stix2 import Filter


def create_threatactor(stix, nouns, adjectives, countries, fs):

    # Create the name, but don't reuse nouns/adjs already chosen
    actors = fs.query(Filter('type', '=', 'threat-actor'))
    names_taken = [ta.name for ta in actors]
    adj = np.random.choice(adjectives)
    while adj in [name.split(' ')[0] for name in names_taken]:
        adj = np.random.choice(adjectives)
    noun = np.random.choice(nouns)
    while noun in [name.split(' ')[1] for name in names_taken]:
        noun = np.random.choice(nouns)
    agent_name = adj + " " + noun

    # target sectors
    desc = list(np.random.choice(
        stix['sectors'], np.random.randint(2, 4), False))

    aliases = [f"APT {1000+(len(actors))}"]
    aliases_taken = []
    for ta in actors:
        aliases_taken.extend(ta.aliases)
    alias = (
        f"{np.random.choice(stix['colors'])} "
        f"{np.random.choice(stix['animals'])}")
    while alias in aliases_taken:
        alias = (
            f'{np.random.choice(stix["colors"])} '
            f'{np.random.choice(stix["animals"])}')
    aliases.append(alias)

    first_seen = date.fromordinal(np.random.randint(
        date.today().replace(year=date.today().year-10).toordinal(),
        date.today().toordinal()))

    last_seen = date.fromordinal(np.random.randint(
        date.today().replace(year=date.today().year-1).toordinal(),
        date.today().toordinal()))
    while last_seen < first_seen:
        last_seen = date.fromordinal(np.random.randint(
            date.today().replace(year=date.today().year-1).toordinal(),
            date.today().toordinal()))

    resource_level = "government"

    threat_actor_types = str(np.random.choice(
        list(stix['threat-actor-type'].keys()),
        p=list(stix['threat-actor-type'].values())))

    motivations = list(np.random.choice(
        stix['attack-motivation'], np.random.randint(2, 4), replace=False))
    primary_motivation = str(motivations[0])

    sophistication = str(np.random.choice(stix['threat-actor-sophistication']))
    secondary_motivations = motivations[1:]
    goals = list(
        np.random.choice(stix['goals'], np.random.randint(2, 4), False))

    apt = ThreatActor(
        name=agent_name,
        aliases=aliases,
        first_seen=first_seen,
        last_seen=last_seen,
        roles='sponsor',
        resource_level=resource_level,
        threat_actor_types=threat_actor_types,
        description=desc,
        primary_motivation=primary_motivation,
        sophistication=sophistication,
        secondary_motivations=secondary_motivations,
        goals=goals
    )
    fs.add(apt)

    # Find countries most likely to host threat actors
    relationships = fs.query([
        Filter("type", "=", "relationship"),
        Filter("relationship_type", "=", "located-at"),
        Filter("source_ref", "contains", "threat-actor")])
    have_actors = [country.name for country in fs.query([
        Filter("type", "=", "location"),
        Filter("id", "in", [r.target_ref for r in relationships])])]
    if threat_actor_types == "terrorist":
        attr_countries = [
            country.name for country in countries
            if hasattr(country, 'terrorism') and
            country.name not in have_actors]
    elif threat_actor_types == "nation-state":
        attr_countries = [
            (country.name, country.percent_GDP_on_military)
            for country in countries
            if hasattr(country, 'international_disputes') and
            country.name not in have_actors]
        attr_countries.sort(key=lambda x: x[1])
        attr_countries = [country[0] for country in attr_countries]
    else:
        attr_countries = [
            country.name for country in countries
            if country.name not in have_actors]
    if len(attr_countries) == 0:
        attr_countries = [
            country.name for country in countries
            if country.name not in have_actors]
    # Set attribution
    country = fs.query([
        Filter("type", "=", "location"),
        Filter("name", "=", attr_countries.pop())])
    fs.add(Relationship(apt, 'located-at', country[0]))


def save(directory, filetype, fs, fs_real):
    """Saves the attributes of the Threat Actor to a specified file.

    Parameters
    ----------
    directory : str
        Path to save output
    filetype : str
        For output file with country data (json or pdf)

    Raises
    ------
    NotImplementedError
        If unsupported filetype is passed in.
    """

    agents = fs.query(Filter("type", "=", "threat-actor"))
    if filetype == 'json':
        for actor in agents:
            filename = directory + actor.name.replace(' ', '') + ".json"
            with open(filename, 'w') as f:
                json.dump(actor.__dict__, f)
            f.close()
    elif filetype == 'pdf':
        ss = getSampleStyleSheet()  # Set up the PDF template

        # Obtain info for each APT and output to PDF
        for iset in agents:
            pdf = platy.SimpleDocTemplate(
                directory + iset.name.replace(' ', '') + ".pdf")
            flowables = []

            relationships = fs.query([
                Filter("type", "=", "relationship"),
                Filter("source_ref", "=", iset.id)])
            ttps, tools, malwares = [], [], []
            for r in relationships:
                if "attack-pattern" in r.target_ref:
                    ttps.append(r.target_ref)
                elif "tool" in r.target_ref:
                    tools.append(r.target_ref)
                elif "malware" in r.target_ref:
                    malwares.append(r.target_ref)
                elif "location" in r.target_ref:
                    countries = fs.query([
                        Filter("type", "=", "location"),
                        Filter("id", "=", r.target_ref)])

            flowables.append(platy.Paragraph(iset.name, ss['Heading1']))
            p = (
                f'{iset.name} is a {iset.resource_level} backed '
                f'{iset.threat_actor_types[0]} group also known as '
                f'{" or ".join(iset.aliases)}, first seen in '
                f'{iset.first_seen.strftime("%B %Y")}. It is attributed to the'
                f' state of {countries[0].name} as a {iset.roles[0]} of '
                f'malicious cyber activity. Its level of sophistication is '
                f'{iset.sophistication}, and its primary motivation is '
                f'{iset.primary_motivation}, though it is sometimes motivated '
                f'by {" and ".join(iset.secondary_motivations)}. '
                f'{iset.description}.')
            flowables.append(platy.Paragraph(p, ss['BodyText']))
            p = iset.name+"'s goals are "
            flowables.append(platy.Paragraph(p, ss['BodyText']))
            bullets = []
            for g in iset.goals:
                p = platy.Paragraph(g, ss['Normal'])
                bullets.append(platy.ListItem(p, leftIndent=35))
            flowables.append(platy.ListFlowable(bullets, bulletType='bullet'))

            flowables.append(platy.Paragraph('Tools', ss['Heading2']))
            p = "This threat actor is known to use the following tools."
            flowables.append(platy.Paragraph(p, ss['BodyText']))
            t_s = [
                fs_real.query([
                    Filter("type", "=", "tool"),
                    Filter("id", "=", t)])[0].name
                for t in tools][:10]
            bullets = []

            for tool in sorted(t_s, key=str.casefold):
                p = platy.Paragraph(tool, ss['Normal'])
                bullets.append(platy.ListItem(p, leftIndent=35))

            flowables.append(platy.ListFlowable(bullets, bulletType='bullet'))

            flowables.append(platy.Paragraph('Malware', ss['Heading2']))
            p = "This threat actor is known to use the following malware."
            flowables.append(platy.Paragraph(p, ss['BodyText']))
            m_s = [
                fs_real.query([
                    Filter("type", "=", "malware"),
                    Filter("id", "=", m)])[0].name
                for m in malwares][:5]
            bullets = []
            for malware in sorted(m_s, key=str.casefold):
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
                attributed to {iset.name}, though there may be others:"
            flowables.append(platy.Paragraph(p, ss['BodyText']))
            sightings = fs.query([
                Filter("type", "=", "sighting"),
                Filter("sighting_of_ref", "=", iset.id)])
            r_nums = [
                str(s.first_seen).replace('-', '') for s in sightings][:15]
            bullets = []
            for r in sorted(r_nums):
                p = platy.Paragraph(
                    r.replace(' ', '_').replace(':', '')[:15], ss['Normal'])
                bullets.append(platy.ListItem(p, leftIndent=35))
            flowables.append(platy.ListFlowable(bullets, bulletType='bullet'))

            pdf.build(flowables)
    else:
        raise NotImplementedError(
            f"Output file type, {filetype}, not supported")


def create_organization(stix, fs, country, org_names, assessment):

    name = np.random.choice(org_names)
    revenue = int(np.random.chisquare(1) * 10000)
    while revenue == 0:
        revenue = int(np.random.chisquare(1) * 10000)
    sector = np.random.choice(stix['sectors'])

    description = {
        "Background": {
            "headquarters": country,
            "number of employees": "{:,}".format(
                np.random.randint(500, 15000)),
            "annual revenue": "$"+"{:,}".format(revenue)+" million"
        },
        "Network": {
            "size": np.random.randint(1, 100)
        }
    }

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
    description["Security Posture"] = {
        "vulnerability": int(score/313 * 100),
        "vulns": vulns
    }

    # Add asset to the STIX data store
    organization = Identity(
        name=name,
        identity_class='organization',
        sectors=sector,
        description=json.dumps(description)
    )
    fs.add(organization)

    # Tie organization to country (headquarters)
    country_id = fs.query([
        Filter('type', '=', 'location'), Filter("name", "=", country)])[0].id
    fs.add(Relationship(organization, 'located-at', country_id))
