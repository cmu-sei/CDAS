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

import argparse
from datetime import datetime, timedelta
import json
import numpy as np
import os
import pkg_resources
import shutil
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
        'defenders': '',
        'threat-actors': '',
        'malware': '',
        'geoseed.json': '',
        'tools': '',
        'ttps': ''
        }

    print("Setting up directories...")
    # Set up the Output directory
    if not args.output_directory:
        args.output_directory = config['output']['output_directory']
    if args.output_directory == "":
        raise Exception(f'No output directory specified')
    output_dir = filestore.FileStore(
        args.output_directory, "output", write=True)

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
        if 'relationships.json' in input_fs:
            with open(os.path.join(
                    args.input_directory,
                    'relationships.json')) as json_file:
                relationships = json.load(json_file)
            json_file.close()
        else:
            with open(pkg_resources.resource_filename(
                    __name__,
                    'assets/mitre_cti/relationships.json')) as json_file:
                relationships = json.load(json_file)
            json_file.close()
    else:
        with open(pkg_resources.resource_filename(
                __name__, 'assets/mitre_cti/relationships.json')) as json_file:
            relationships = json.load(json_file)
        json_file.close()

    # Set the file stores for malware, tools, and TTPs
    if datastore['malware'] == '':
        malware_fs = filestore.FileStore(pkg_resources.resource_filename(
                __name__, "assets/mitre_cti/malware"), context.Malware)
    else:
        malware_fs = filestore.FileStore(datastore['malware'], context.Malware)
    if datastore['tools'] == '':
        tools_fs = filestore.FileStore(pkg_resources.resource_filename(
                __name__, "assets/mitre_cti/tools"), context.Tool)
    else:
        tools_fs = filestore.FileStore(datastore['tools'], context.Tool)
    if datastore['ttps'] == '':
        ttp_fs = filestore.FileStore(pkg_resources.resource_filename(
                __name__, "assets/mitre_cti/attack-patterns"), context.Ttp)
    else:
        ttp_fs = filestore.FileStore(datastore['ttps'], context.Ttp)

    # Load or create country data
    if datastore['countries'] != '':
        # Using custom data
        print("Loading custom country data...")
        countries_fs = filestore.FileStore(
            datastore['countries'], context.Country)
    elif config['countries']['randomize'] is True:
        print("Creating fake countries...")
        countries_fs = filestore.FileStore(
            os.path.join(config['output']['temp_directory'], 'countries'),
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
            country_names[country.id] = country.name

        for c in country_names:
            country = countries_fs.get(c)
            country.update(country_names)
            countries_fs.save(country, overwrite=True)
    else:
        # Using country data files instead of random generation
        print("Loading default country data...")
        countries_fs = filestore.FileStore(
            pkg_resources.resource_filename(
                __name__, 'data/cia_world_factbook/'), context.Country)

    # Output country data
    for ot in config['output']['output_types']:
        path = args.output_directory + "/" + ot
        os.mkdir(path)
        os.mkdir(path + '/countries/')
        for country in countries_fs.get(
                [i[0] for i in countries_fs.query("SELECT id")]):
            output_dir.output(ot+'/countries', country, ot)
        if ot == "html":
            html_src = pkg_resources.resource_filename(
                __name__, 'assets/html_templates')
            html_templates = os.listdir(html_src)
            for f in html_templates:
                shutil.copy(html_src + '/' + f, path)
            f = open(path+'/COUNTRY.html', 'r')
            c_template = f.read()
            f.close()
            for country in countries:
                f = open(path + '/countries/' + country.name + '.html', 'w')
                f.write(c_template.replace('COUNTRY', country.name))
                f.close()
            os.remove(path+'/COUNTRY.html')

    # Load or create actor data
    with open(pkg_resources.resource_filename(
            __name__,
            "assets/stix_vocab.json"), encoding='utf-8') as json_file:
        stix_vocab = json.load(json_file)
    json_file.close()
    tools = tools_fs.get([name[0] for name in tools_fs.query("SELECT id")])
    malwares = malware_fs.get([n[0] for n in malware_fs.query("SELECT id")])
    ttps = ttp_fs.get([name[0] for name in ttp_fs.query("SELECT id")])

    if datastore['threat-actors'] != '':
        print("Loading custom threat actor data...")
        # Using custom threat actors provided by the user in the input folder
        threat_actor_fs = filestore.FileStore(
            datastore['threat-actors'], agents.ThreatActor)
    elif config['agents']['randomize_threat_actors'] is True:
        print("Creating fake threat actors...")
        threat_actor_fs = filestore.FileStore(
            os.path.join(config['output']['temp_directory'], 'threat-actors'),
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
            actor.create_fake_history(relationships, tools, malwares, ttps,
                stix_vocab['threat-actor-sophistication'])
            actors += 1
    else:
        print("Loading default threat actor data...")
        threat_actor_fs = filestore.FileStore(
            pkg_resources.resource_filename(
                __name__, 'assets/mitre_cti/threat-actors/'),
            agents.ThreatActor)

    # Output threat actor reports
    actors = threat_actor_fs.get(
        [name[0] for name in threat_actor_fs.query("SELECT id")])
    for ot in config['output']['output_types']:
        os.mkdir(args.output_directory + "/" + ot + '/actors/')
        for apt in actors:
            output_dir.output(ot+'/actors', apt._save(
                relationships, tools_fs, malware_fs, ttp_fs), ot)

    # Create or load defending organizations
    if datastore['defenders'] != '':
        print("Loading custom defender data...")
        # Using custom defenders provided by the user in the input folder
        defender_fs = filestore.FileStore(
            datastore['defenders'], agents.Defender)
    else:
        print("Creating random defending organizations...")
        defender_fs = filestore.FileStore(
            os.path.join(config['output']['temp_directory'], 'defenders'),
            agents.Defender, write=True)
        with open(pkg_resources.resource_filename(
                __name__,
                config['defenders']['org_names'])) as f:
            org_names = f.read().splitlines()  # defender name possibilities
        f.close()
        with open(pkg_resources.resource_filename(
                __name__, 'assets/NIST_assess.json'),
                encoding='utf-8') as json_file:
            assessment = json.load(json_file)
        json_file.close()

        # Get a list of country names the defenders may be assigned to
        countries = [c[0] for c in countries_fs.query("SELECT name")]
        if isinstance(config['defenders']['countries'], list):
            for c in config['defenders']['countries']:
                if c not in countries:
                    raise Exception(
                        f'Country {c} in config file entry for "defenders":'
                        f'"countries" is not in the Country file store.')
            countries = config['defenders']['countries']
        elif config['defenders']['countries'] == "ANY":
            pass
        else:
            raise Exception(
                f"Config file entry for 'defenders':'countries': "
                f"{config['defenders']['countries']} is not an accepted value."
                f" Options are \"ANY\" or a list of country names.")
        if config['defenders']['sectors'] == "ANY":
            sectors = stix_vocab['sectors']
        elif isinstance(config['defenders']['sectors'], list):
            sectors = config['defenders']['sectors']
        else:
            raise Exception(
                f'{config["defenders"]["sectors"]} is not a recognized option '
                f'for "defenders":"sectors" in the config file. Options are '
                f'"ANY" or a list of sector names.')
        for c in countries:
            defs = 0
            while defs < config['defenders']['number_per_country']:
                d = agents.Defender(sectors, c, org_names, assessment)
                defender_fs.save(d)
                defs += 1

    # Output defender info
    defenders = defender_fs.get(
        [name[0] for name in defender_fs.query("SELECT id")])
    for ot in config['output']['output_types']:
        os.mkdir(args.output_directory + "/" + ot + '/defenders/')
        for d in defenders:
            output_dir.output(ot+'/defenders', d, ot)

    # Create or load networks of defenders

    # Output network information
    

    # Run simulation
    print('Running simulation...')
    events_fs = filestore.FileStore(
        os.path.join(config['output']['temp_directory'], 'events'),
        context.Event, write=True)
    # For now, we're assuming all of the attackers decide to attack the one
    # defender, who is too dumb to make changes the network
    simulator.simulate(
        actors, defenders, tools, malwares, events_fs, relationships, start)
    # We don't know ahead of time how many moves will be made, so go back to 
    # the events and set to the desired time frame
    start = datetime.strptime(
        config["simulation"]['time_range'][0], '%Y-%m-%d')
    end = datetime.strptime(config["simulation"]['time_range'][1], '%Y-%m-%d')
    time_increment = (end - start)/num_events
    print("@TODO: Event date times...")

    # Create output files
    print('Saving output...')
    # Map
    try:
        map_matrix.plot_map(args.output_directory, **country_names)
    except NameError:
        pass

    for ot in config['output']['output_types']:
        print(f'    {ot}...')
        path = args.output_directory + "/" + ot
        os.mkdir(path + '/reports/')
        print(f'\t  Events...')
        for e in events_fs.get([i[0] for i in events_fs.query("SELECT id")]):
            output_dir.output(ot+'/reports', e, ot)

    shutil.rmtree(config['output']['temp_directory'])

    print('Done')


if __name__ == "__main__":
    main()
