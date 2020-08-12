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
from stix2.v21 import Relationship, IntrusionSet, Identity
from stix2 import Filter


def create_threatactor(stix, nouns, adjectives, countries, fs):
    """
    Create a  basic threat actor profile, including country attribution, and 
    save to the given data store. 

    Parameters
    ----------
    stix : dictionary
        Seed vocabulary for APT profiles
    nouns : list
        Words available for first word in APT name
    adjectives : list
        Words avialables for second word in APT name
    countries : list
        List of country objects (for setting attribution)
    fs : FileSystemStore object
        Where to locate the APT data
    """

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

    sophistication = str(np.random.choice(stix['threat-actor-sophistication']))
    actor_type = np.random.choice(
        list(stix["threat-actor-type"].keys()),
        p=list(stix["threat-actor-type"].values()))

    # target sectors
    sectors = list(np.random.choice(
        stix['sectors'], np.random.randint(2, 4), False))
    
    description = {
        'sophistication': sophistication,
        'actor_type': actor_type,
        'target_sectors': sectors
    }

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

    motivations = list(np.random.choice(
        stix['attack-motivation'], np.random.randint(2, 4), replace=False))
    primary_motivation = str(motivations[0])
    secondary_motivations = motivations[1:]
    goals = list(
        np.random.choice(stix['goals'], np.random.randint(2, 4), False))

    apt = IntrusionSet(
        name=agent_name,
        aliases=aliases,
        first_seen=first_seen,
        last_seen=last_seen,
        resource_level=resource_level,
        description=json.dumps(description),
        primary_motivation=primary_motivation,
        secondary_motivations=secondary_motivations,
        goals=goals
    )
    fs.add(apt)

    # Find countries most likely to host threat actors
    relationships = fs.query([
        Filter("type", "=", "relationship"),
        Filter("relationship_type", "=", "located-at"),
        Filter("source_ref", "contains", "intrusion-set")])
    have_actors = [country.name for country in fs.query([
        Filter("type", "=", "location"),
        Filter("id", "in", [r.target_ref for r in relationships])])]
    if actor_type == "terrorist":
        attr_countries = [
            country.name for country in countries
            if hasattr(country, 'terrorism') and
            country.name not in have_actors]
    elif actor_type == "nation-state":
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
        if len(attr_countries) == 0:
            # all of the countries already have at least one actor
            attr_countries = [country.name for country in countries]
    # Set attribution
    country = fs.query([
        Filter("type", "=", "location"),
        Filter("name", "=", attr_countries.pop())])
    fs.add(Relationship(apt, 'located-at', country[0]))


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

    if filetype == 'json':
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


def create_organization(stix, fs, country, org_names, assessment):
    """
    Generate a company profile and save to the STIX data store

    Parameters
    ----------
    stix : dictionary
        Seed vocabulary for organization profiles
    fs : FileSystemStore object
        Data store to save organization information
    country : string
        Name of country with which to associate organization
    org_names : list
        organization names to choose from
    assessment : dictionary
        representation of NIST 800-171 assessment table
    """

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
