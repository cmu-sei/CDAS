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

import logging
import json
import numpy as np
import uuid
import string
from datetime import datetime, timedelta
import reportlab.platypus as platy
from reportlab.lib.styles import getSampleStyleSheet
from cyberdem import filesystem
from . import context


def random_indicator(itype):
    """
    Generate a random indicator of the specified type

    Parameters
    ----------
    itype : string
        The type of indicator to be generated.

    Raises
    -------
    ValueError
        if the itype given is not a known type

    Returns
    -------
    indicator : string
        A randomly generated indicator of the specified type
    """

    if itype == 'ip-src':
        ipv4 = [str(quad) for quad in np.random.randint(0, 255, 4)]
        indicator = ".".join(ipv4)
    elif itype == 'domain':
        generic_tlds = ['.com', '.net', '.org', '.site', '.biz']
        name = np.random.choice(list(string.ascii_letters+string.digits), 10)
        indicator = ''.join(name) + np.random.choice(generic_tlds)
    else:
        raise ValueError(
            f"{itype} is not an available type for random_indicator")
    return indicator


def simulate(
        actors, defenders, defend, events_fs, relationships, soph_levels,
        start, time_increment, rounds, budget_times):

    if defend:
        for defender in defenders:
            defender.current_budget = float(
                defender.budget[1:].replace(',', ''))

    t = 0
    s_time = start
    budget_increment = rounds/budget_times
    update_budget = 1
    while t < rounds:
        logging.info(f'Round: {t+1}')
        for actor in actors:
            # Decide if the actor can attack during this round. The more
            # sophisticated the actor, the more often they can attack. For the
            # purpose of calculations, the strongest actor is level 1, the
            # levels go up as the actors get weaker.
            if t % soph_levels[actor.sophistication] == 0:
                # Actor picks a target
                # @TODO - currently a random target make this more logical
                target = np.random.choice(defenders)
                logging.debug(f'\t{actor.name} attacking {target.name}...')
                # @TODO - load target's network
                for r in relationships:
                    if r[0] == target.id and r[1] == 'owns':
                        network = r[2]
                        break
                event = attack(actor, target, network)
                event.date = s_time
                event.name = "Report_" + s_time.strftime("%Y%m%d_%H%M%S")
                events_fs.save(event)

        if defend:
            # update the defender's budget if the time is right
            if (t+1) % round(update_budget * budget_increment) == 0:
                for defender in defenders:
                    amount = float(defender.budget[1:].replace(',', '')) / \
                        budget_times
                    defender.current_budget += amount
                    logging.debug(
                        f'\tUpdating {defender.name}\'s budget by {amount} to '
                        f'{defender.current_budget}')
                update_budget += 1
            for defender in defenders:
                # if the defender can attack during this round
                if t % defender.sophistication == 0:
                    print(defender.name)
        t += 1
        s_time += time_increment


def attack(actor, target, network):
    # @TODO - add some tools, ttps, malware, etc
    itype = np.random.choice(['ip-src', 'domain'])
    indicators = {itype: random_indicator(itype)}

    # @TODO - this probably shouldn't be random...
    success = np.random.choice([True, False])

    description = (
        f"The company {target.name} was attacked by {actor.name}. It is "
        f"believed that the attack was "
        f"{'successful' if success else 'unsuccessful'}.")

    event = context.Event(
        id='event--'+str(uuid.uuid4()),
        description=description,
        target=target.id,
        indicators=indicators,
        attack_successful=success,
        threat_actor=actor.id)
    return event


def defend():
    pass
