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

def simulate(actors, defender, tools, malwares, events_fs, relationships):

    t = 0  # Set the time step

    for agent in actors:
        # Pick a random target  @TODO - make this more logical later
        target = np.random.choice(orgs)

        r_num = str(
            start_date).replace('-', '').replace(' ', '_').replace(':', '')
        events_fs.save(context.Event(
            id='event--'+str(uuid.uuid4()),
            name=f"Report #{r_num[:15]}",
            description=description,
            first_seen=start_date,
            sighting_of_ref=agent.id))
        start_date += timedelta(td)

def attack():
    pass