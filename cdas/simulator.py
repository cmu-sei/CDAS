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

import json
import numpy as np
import uuid
import string
from datetime import datetime, timedelta
import reportlab.platypus as platy
from reportlab.lib.styles import getSampleStyleSheet
from . import context


def random_indicator(itype):
    """
    Generate a random indicator of the specified type

    Parameters
    ----------
    itype : string
        The type of indicator to be generated. Choose from ['IPv4 address',
        'domain name']

    Raises
    -------
    ValueError
        if the itype given is not a known type

    Returns
    -------
    indicator : string
        A randomly generated indicator of the specified type
    """

    if itype == 'IPv4 address':
        ipv4 = [str(quad) for quad in np.random.randint(0, 255, 4)]
        indicator = ".".join(ipv4)
    elif itype == 'domain name':
        generic_tlds = ['.com', '.net', '.org', '.site', '.biz']
        name = np.random.choice(list(string.ascii_letters+string.digits), 10)
        indicator = ''.join(name) + np.random.choice(generic_tlds)
    else:
        raise ValueError(
            f"{itype} is not an available type for random_indicator")
    return indicator


def simulate(actors, orgs, tools, malwares, events_fs, relationships, start_date, td):
    """
    Run one round of attacks and defenses with the given data set.

    Each threat actor in the 'actors' parameter takes an opportunity to choose
    and attack a target. The actor chooses a tool (and possibly malware) from
    the specified STIX data sets, and generates a random indicator. The attack
    is either successful or unsuccessful. 

    Parameters
    ----------
    actors : list of ThreatActor objects

    orgs : list of Identity objects
        STIX formatted Identity set filtered for identity_class=organization
    tools : list of Tool objects
        STIX formatted tool set to choose from
    malwares : list of Malware objects
        STIX formatted malware set to choose from
    fs : FileSystemStore
        Data store to save events
    start_date : datetime
        Start date for the events in the current round of the simulation
    td : time delta
        Time between each cyber event
    """

    # Reference to convert the agent's sophistication level to an integer
    skill_levels = {
        "minimal": 1,
        "intermediate": 2,
        "advanced": 3,
        "expert": 4,
        "innovator": 5,
        "strategic": 6
    }

    for agent in actors:
        # Pick a random target  @TODO - make this more logical later
        target = np.random.choice(orgs)

        success = np.random.choice([True, False])
        tool = np.random.choice(tools)
        if (agent.id,'relationship',tool.id) not in relationships:
            relationships.append((agent.id, 'uses', tool.id))
        indicator_type = np.random.choice(['IPv4 address', 'domain name'])
        used_malware = np.random.choice(['yes', 'no'], p=[.25, .75])
        if used_malware == 'yes':
            malware = malwares[np.random.randint(0,len(malwares))]
            if (agent.id, 'uses', malware.id) not in relationships:
                relationships.append((agent.id, 'uses', malware.id))

        description = f'On {str(start_date)[:10]}, '
        if success is True:
            description += 'an attacker successfully attacked a company named '
        else:
            description += 'an attack was attempted against a company named '
        description += (
            f'{target.name.upper()} located in the country of '
            f'{target.headquarters}. The '
            f'attacker used the tool, {tool.name}, during its attack. ') 
        if hasattr(agent,'goals'):
            description += (
                f'It is believed the goal of the attack was to '
                f'{np.random.choice(agent.goals)}.')
        description += (
            f' One of the indicators discovered was the {indicator_type}, '
            f'{random_indicator(indicator_type)}.')
        if used_malware == 'yes':
            description += (
                f' The attacker also attempted to use the malware '
                f'{malware.name}.')

        r_num = str(
            start_date).replace('-', '').replace(' ', '_').replace(':', '')
        events_fs.save(context.Event(
            id='event--'+str(uuid.uuid4()),
            name=f"Report #{r_num[:15]}",
            description=description,
            first_seen=start_date,
            sighting_of_ref=agent.id))
        start_date += timedelta(td)
