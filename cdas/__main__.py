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

import argparse
from datetime import datetime, timedelta
import json
import numpy as np
import os
import pkg_resources
import shutil
from stix2 import FileSystemStore, FileSystemSource, Filter
import sys
# Import custom modules
from . import context, agents, simulator, filestore


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config-file", required=True,
        help="configuration file (json)")
    parser.add_argument(
        "-i", "--input-directory",
        help="directory for specifying custom data")
    parser.add_argument(
        "-o", "--output-directory",
        help="directory for storing results")

    args = parser.parse_args()

    # Load the configuration file
    with open(args.config_file, 'r') as f:
        config = json.load(f)
    f.close()

    datastore = {
        'countries': '',
        'threat-actors': '',
        'malware': '',
        'geoseed.json': '',
        'tools': ''}

    # Set up the Output directory
    if not args.output_directory:
        args.output_directory = config['output']['output_directory']
    if args.output_directory == "":
        raise Exception(f'No output directory specified')
    output_dir = filestore.FileStore(args.output_directory, "output", write=True)

    # Set up the temp directory
    if config['output']['temp_directory'] == "":
        raise Exception(f'No temporary directory specified')
    temp_dir = filestore.FileStore(
        config['output']['temp_directory'], "temp", write=True)

    # Check the input folder if provided
    if not args.input_directory:
        args.input_directory = config['output']['input_directory']
    if args.input_directory != "":
        input_fs = os.listdir(args.input_directory)
        for f in input_fs:
            if f.lower() not in datastore.keys():
                raise Exception(
                    f'{f} in {args.input_directory} is not allowed as an '
                    f'input. These are allowed: {datastore.keys()}')
            else:
                datastore[f.lower()] = os.path.join(args.input_directory, f)

    # Set the file stores for malware and tools
    if datastore['malware'] == '':
        malware_fs = filestore.FileStore(pkg_resources.resource_filename(
                __name__, "assets/mitre_cti/malware"), 'malware')
    else:
        malware_fs = filestore.FileStore(datastore['malware'], 'malware')
    if datastore['tools'] == '':
        tools_fs = filestore.FileStore(pkg_resources.resource_filename(
                __name__, "assets/mitre_cti/tool"), 'tools')
    else:
        tools_fs = filestore.FileStore(datastore['tools'], 'tools')

    # Load or create country data
    if datastore['countries'] != '':
        # Using custom data
        countries_fs = filestore.FileStore(
            datastore['countries'], context.Country)
    elif config['countries']['randomize'] is True:
        countries_fs = filestore.FileStore(
            os.path.join(config['output']['temp_directory'],'countries'),
            context.Country, write=True)
        
        # Load the seed file
        if datastore['geoseed.json'] == '':
            datastore['geoseed.json'] = pkg_resources.resource_filename(
                __name__, "data/geoseed.json")
        with open(datastore['geoseed.json'], encoding='utf-8') as f:
            context_options = json.load(f)
        f.close()

        map_matrix = context.Map(
            config['countries']['random_vars']['num_countries'])

        country_names = {}   
        for c in range(0, config['countries']['random_vars']['num_countries']):
            country = context.Country(context_options, map_matrix.map)
            countries_fs.save(country)
            country_names[str(country.id)] = country.name
        for c in country_names:
            country = countries_fs.get(country_names[c])
            country.update(country_names)
            countries_fs.save(country, overwrite=True)
    else:
        # Using country data files instead of random generation
        countries_fs = filestore(
            pkg_resources.resource_filename(
                __name__, 'data/cia_world_factbook/'), context.Country)

    # Load or create actor data
    print("Creating threat actors...")
    with open(pkg_resources.resource_filename(
            __name__,
            "assets/stix_vocab.json"), encoding='utf-8') as json_file:
        stix_vocab = json.load(json_file)
    json_file.close()

    if datastore['threat-actors'] != '':
        # Using custom threat actors provided by the user in the input folder
        threat_actor_fs = filestore.FileStore(datastore['threat-actors'],
            agents.ThreatActor)
    elif config['agents']['randomize_threat_actors'] is True:
        threat_actor_fs = filestore.FileStore(
            os.path.join(config['output']['temp_directory'],'threat-actors'),
            agents.ThreatActor, write=True)
        with open(pkg_resources.resource_filename(
                __name__,
                config['agents']['random_variables']['actor_name_1']), 
                encoding='utf-8') as f:
            actor_name_1 = [line.rstrip() for line in f]
        f.close()
        with open(pkg_resources.resource_filename(
                __name__,
                config['agents']['random_variables']['actor_name_2']), 
                encoding='utf-8') as f:
            actor_name_2 = [line.rstrip() for line in f]
        f.close()
        actors = 1
        while actors <= config['agents']['random_variables']['num_agents']:
            actor = agents.ThreatActor(
                stix_vocab, actor_name_1, actor_name_2, countries_fs, 
                threat_actor_fs)
            threat_actor_fs.save(actor)
            actors += 1
    else:
        # no randomization - use default set
        threat_actor_fs = filestore(
            pkg_resources.resource_filename(
                __name__, 'assets/mitre_cti/intrusion-set/'), agents.ThreatActor)

    # Create organizations
    print('Creating organizations...')
    with open(pkg_resources.resource_filename(
            __name__,
            config['agents']['org_variables']['org_names'])) as f:
        org_names = f.read().splitlines()  # organization name possibilities
    f.close()
    with open(pkg_resources.resource_filename(
            __name__, 'assets/NIST_assess.json'), encoding='utf-8') as json_file:
        assessment = json.load(json_file)
    json_file.close()
    organizations_fs = filestore.FileStore(
            os.path.join(config['output']['temp_directory'],'organizations'),
            agents.Organization, write=True)
    for c in countries_fs.query("SELECT name"):
        orgs = 0
        while orgs < config['agents']['org_variables']["orgs_per_country"]:
            org = agents.Organization(stix_vocab, c, org_names, assessment)
            organizations_fs.save(org)
            orgs += 1

    # Run simulation
    print('Running simulation...')
    events_fs = filestore.FileStore(
            os.path.join(config['output']['temp_directory'],'events'),
            'events', write=True)
    start = datetime.strptime(
        config["simulation"]['time_range'][0], '%Y-%m-%d')
    end = datetime.strptime(config["simulation"]['time_range'][1], '%Y-%m-%d')
    td = end - start
    actors = threat_actor_fs.get(
        [name[0] for name in threat_actor_fs.query("SELECT name")])
    orgs = organizations_fs.get(
        [name[0] for name in organizations_fs.query("SELECT name")])
    tools = tools_fs.get(
        [name[0] for name in tools_fs.query("SELECT name")])
    malwares = malware_fs.get(malware_fs.query("SELECT name"))
    for r in range(1, int(config["simulation"]['number_of_rounds'])+1):
        print(f'\tRound {r}')
        simulator.simulate(
            actors, orgs, tools, malwares, events_fs, start,
            td.days/(config["simulation"]['number_of_rounds']*len(actors)))
        start += timedelta(
            days=td.days/config["simulation"]['number_of_rounds'])

    # Create output files
    print('Saving output...')
    # Map
    try:
        map_matrix.plot_map(args.output, **country_names)
    except NameError:
        pass

    for ot in config['output']['output_types']:
        print(f'\t{ot}')
        path = args.output + "/" + ot
        if ot == "stix":
            shutil.copytree(temp_path, path)
        else:
            os.mkdir(path)
            os.mkdir(path + '/countries/')
            os.mkdir(path + '/actors/')
            os.mkdir(path + '/reports/')
            os.mkdir(path + '/organizations/')
            for country in countries:
                country.save(path + '/countries/', ot)
            apts = threat_actor_fs.query(Filter("type", "=", "intrusion-set"))
            for apt in apts:
                agents.save(apt, path + '/actors/', ot, fs_gen, fs_real)
            events = fs_gen.query(Filter("type", "=", "sighting"))
            for e in events:
                simulator.save(
                    e, threat_actor_fs, fs_real, path + '/reports/', ot)
            for org in orgs:
                agents.save_org(
                    org, path + '/organizations/', ot, assessment)
        if ot == "html":
            html_src = pkg_resources.resource_filename(
                __name__, 'assets/html_templates')
            html_templates = os.listdir(html_src)
            for f in html_templates:
                shutil.copy(html_src + '/' + f, path)
            f = open(path+'/COUNTRY.html','r')
            c_template = f.read()
            f.close()
            for country in countries:
                f = open(path + '/countries/' + country.name + '.html','w')
                f.write(c_template.replace('COUNTRY',country.name))
                f.close()
            os.remove(path+'/COUNTRY.html')

    shutil.rmtree(temp_path)

    print('Done')


if __name__ == "__main__":
    main()
