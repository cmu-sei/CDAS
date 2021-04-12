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
import logging
import numpy as np
import os
import pkg_resources
import shutil
import sys
from cyberdem import widgets, filesystem
import uuid
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
    parser.add_argument('--verbose', '-v', action='count', default=0,
        help="v for basic status, vv for detailed status")

    args = parser.parse_args()
    if args.verbose == 1:
        logging.basicConfig(
            format='%(message)s', level=logging.INFO)
    elif args.verbose == 2:
        logging.basicConfig(
            format='%(message)s', level=logging.DEBUG)

    # Load the configuration file
    with open(args.config_file, 'r') as f:
        config = json.load(f)
    f.close()

    datastore = {
        'countries': '',
        'defenders': '',
        'threat-actors': '',
        'malware': '',
        'networks': '',
        'geoseed.json': '',
        'relationships.json': '',
        'tools': '',
        'ttps': ''
        }

    logging.info("Setting up directories...")
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
    filestore.FileStore(
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
                    f'input. These are allowed: {", ".join(list(datastore.keys()))}')
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
        logging.info("Loading custom country data...")
        countries_fs = filestore.FileStore(
            datastore['countries'], context.Country)
    elif config['countries']['randomize'] is True:
        logging.info("Creating fake countries...")
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
        logging.info("Loading default country data...")
        countries_fs = filestore.FileStore(
            pkg_resources.resource_filename(
                __name__, 'data/cia_world_factbook/'), context.Country)

    # Output country data
    for ot in config['output']['output_types']:
        path = args.output_directory + "/" + ot
        if ot == "html":
            templates = pkg_resources.resource_filename(
                __name__, f'assets/{ot}_templates')
            shutil.copytree(templates,path)
        elif ot == "misp":
            os.mkdir(path)
        else:
            os.mkdir(path)
            os.mkdir(path + '/countries/')
        if ot == 'html':
            f = open(path+'/COUNTRY.html', 'r')
            c_template = f.read()
            f.close()
            os.mkdir(path + '/countries/')
            countries = [c[0] for c in countries_fs.query("SELECT name")]
            countries.sort()
            ul_list = '<ul id="world-map-list">'
            for country in countries:
                f = open(path + '/countries/' + country + '.html', 'w')
                f.write(c_template.replace('COUNTRY', country))
                f.close()
                ul_list += f"<li><a href='countries/{country}.html'>{country}</a></li>"
            os.remove(path+'/COUNTRY.html')
            f = open(path + '/index.html', 'r')
            index = f.read()
            f.close()
            f = open(path + '/index.html', 'w')
            f.write(index.replace('<ul id="world-map-list">', ul_list))
            f.close()
        if ot == 'misp':
            output_dir.save_misp(path+'/country-galaxy-cluster.json', countries_fs)
        else:
            for i in countries_fs.query("SELECT id"):
                country = countries_fs.get(i[0])
                output_dir.output(ot+'/countries', country, ot)

    # Load or create actor data
    with open(pkg_resources.resource_filename(
            __name__,
            "assets/vocabulary.json"), encoding='utf-8') as json_file:
        stix_vocab = json.load(json_file)
    json_file.close()
    names = tools_fs.query("SELECT id")
    tools = [tools_fs.get(name[0]) for name in names]
    names = malware_fs.query("SELECT id")
    malwares = [malware_fs.get(name[0]) for name in names]
    names = ttp_fs.query("SELECT id")
    ttps = [ttp_fs.get(name[0]) for name in names]

    if datastore['threat-actors'] != '':
        logging.info("Loading custom threat actor data...")
        # Using custom threat actors provided by the user in the input folder
        threat_actor_fs = filestore.FileStore(
            datastore['threat-actors'], agents.ThreatActor)
    elif config['agents']['randomize_threat_actors'] is True:
        logging.info("Creating fake threat actors...")
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
        logging.info("Loading default threat actor data...")
        threat_actor_fs = filestore.FileStore(
            pkg_resources.resource_filename(
                __name__, 'assets/mitre_cti/threat-actors/'),
            agents.ThreatActor)

    # Output threat actor reports
    names = threat_actor_fs.query("SELECT id")
    actors = [threat_actor_fs.get(name[0]) for name in names]
    for ot in config['output']['output_types']:
        if ot == 'misp':
            output_dir.save_misp(
                path+'/threat-actor-galaxy-cluster.json', threat_actor_fs)
        else:
            os.mkdir(args.output_directory + "/" + ot + '/threat-actors/')
            for apt in actors:
                output_dir.output(ot+'/threat-actors', apt._save(
                    relationships, tools_fs, malware_fs, ttp_fs), ot)
        if ot == 'html':
            f = open(path+'/APT.html', 'r')
            template = f.read()
            f.close()
            apts = [c[0] for c in threat_actor_fs.query("SELECT name")]
            apts.sort()
            ul_list = '<ul id="threat-actors-list">'
            for apt in apts:
                short_name = apt.replace(' ','')
                f = open(path + '/threat-actors/' + short_name + '.html', 'w')
                f.write(template.replace('APT', short_name))
                f.close()
                ul_list += f"<li><a href='threat-actors/{short_name}.html'>{apt}</a></li>"
            os.remove(path+'/APT.html')
            f = open(path + '/index.html', 'r')
            index = f.read()
            f.close()
            f = open(path + '/index.html', 'w')
            f.write(index.replace('<ul id="threat-actors-list">', ul_list))
            f.close()

    # Create or load defending organizations
    if datastore['defenders'] != '':
        logging.info("Loading custom defender data...")
        # Using custom defenders provided by the user in the input folder
        defender_fs = filestore.FileStore(
            datastore['defenders'], agents.Defender)
    else:
        logging.info("Creating random defending organizations...")
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
                f" Options are \"ANY\" or a list of country names, such as [\""
                f"United States\",\"Andorra\"].")
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
    logging.info('Saving defenders to output folder...')
    names = defender_fs.query("SELECT id")
    defenders = [defender_fs.get(name[0]) for name in names]
    defenders.sort(key=lambda x: x.name)
    for ot in config['output']['output_types']:
        logging.debug('\t'+ot)
        if ot == 'misp':
            output_dir.save_misp(
                path+'/organization-galaxy-cluster.json', defender_fs)
        else:
            os.mkdir(args.output_directory + "/" + ot + '/defenders/')
            for d in defenders:
                output_dir.output(ot+'/defenders', d, ot)
        if ot == 'html':
            f = open(path+'/COMPANY.html', 'r')
            template = f.read()
            f.close()
            ul_list = '<ul id="companies-list">'
            for d in defenders:
                f = open(path + '/defenders/' + d.name.replace(' ','') + '.html', 'w')
                f.write(template.replace('COMPANY', d.name.replace(' ','')))
                f.close()
                ul_list += f"<li><a href='defenders/{d.name.replace(' ','')}.html'>{d.name}</a></li>"
            os.remove(path+'/COMPANY.html')
            f = open(path + '/index.html', 'r')
            index = f.read()
            f.close()
            f = open(path + '/index.html', 'w')
            f.write(index.replace('<ul id="companies-list">', ul_list))
            f.close()

    # Create or load networks of defenders
    network_fs = filestore.FileStore(
        os.path.join(config['output']['temp_directory'], 'networks'),
        'Networks', write=True)
    if datastore['networks'] != '':
        logging.info("Loading custom network data...")
        # Using custom networks provided by the user in the input folder
        network_ids = []
        for f in os.listdir(datastore['networks']):
            # for each file (if flat file) or folder (if CyberDEM raw), create
            # a cyberdem directory and copy the data in as CyberDEM raw format
            if f.endswith('.json'):
                netname = f[9:-5]
            else:
                netname = f[9:]
            try:
                uuid.UUID(netname, version=4)
            except ValueError:
                raise ValueError(
                    f'{f} is not a properly formatted network name. Should be '
                    f'\'network--[uuidv4 string]\'')
            network_ids.append('network--'+netname)
            src = os.path.join(datastore['networks'], f)
            dst = os.path.join(config['output']['temp_directory'],
                    'networks', 'network--'+netname)
            if os.path.isfile(src):
                fs = filesystem.FileSystem(dst)
                fs.load_flatfile(src)
            else:
                shutil.copytree(src, dst)
        # Add relationships of networks to defenders
        logging.info("Applying networks to defenders...")
        # if defender input was given and the defender to network relationships
        # were provided in a relationships file 
        already_assigned = []
        for d in defenders:
            rels = [r for r in relationships if d.id in r and any(item in r for item in network_ids)]
            if len(rels) == 1:
                already_assigned.append(d.id)
        # ensure all defenders get a network
        if len(already_assigned) > 0 and len(already_assigned) < len(defenders):
            raise IndexError(
                'Not all defenders have assigned networks in the relationsihp '
                'file. Assign all defenders to a network in the relationships '
                'file, or do not assign any relationships between defenders '
                'and networks (networks will be randomly assigned.')
        # otherwise, no relationship mapping was provided, randomly and evenly assign networks to defenders
        if len(already_assigned) == 0:
            i = 0
            while i < len(defenders):
                net_id = i % len(network_ids)
                relationships.append((defenders[i].id, 'owns', network_ids[net_id]))
                i += 1
    else:
        logging.info("Creating random networks for defenders...")
        for d in defenders:
            net_name = 'network--'+str(uuid.uuid4())
            fs = filesystem.FileSystem(os.path.join(
                config['output']['temp_directory'], 'networks', net_name))
            widgets.generate_network(10, 10, fs)
            relationships.append((d.id, 'owns', net_name))

    # Output networks info
    logging.info('Saving networks to output folder...')
    for ot in config['output']['output_types']:
        logging.debug('\t' + ot)
        dst = os.path.join(args.output_directory, ot, 'networks')
        if ot == 'misp':
            logging.info('Note: Networks are not included in MISP output')
            continue
        else:
            os.mkdir(dst)
        for network in os.listdir(network_fs.path):
            fs = filesystem.FileSystem(os.path.join(network_fs.path, network))
            owner_id = [
                r[0] for r in relationships
                if r[1] == 'owns' and r[2] == network][0]
            owner_name = defender_fs.query(f'SELECT name WHERE id="{owner_id}"')
            if ot == 'json':
                fs.save_flatfile(os.path.join(dst, network + '.json'))
            elif ot == 'html':
                fs.save_flatfile(os.path.join(
                    dst, owner_name[0][0].replace(' ','') + 'Network.json'))
                net_sum = widgets.network_summary(fs)
                net_sum['name'] = owner_name[0][0] + ' Network'
                output_dir.output_network_file(ot + '/networks', net_sum, ot)
            elif ot == 'pdf':
                net_sum = widgets.network_summary(fs)
                net_sum['name'] = owner_name[0][0] + ' Network'
                output_dir.output_network_file(ot + '/networks', net_sum, ot)
            else:
                pass
        if ot == 'json':
            # include the relationships file with json output
            fn = os.path.join(args.output_directory, ot, 'relationships.json')
            with open(fn, 'w') as fp:
                json.dump(relationships, fp)
            fp.close()
        if ot == 'html':
            os.remove(os.path.join(
                    args.output_directory, ot, 'NETWORK.html'))

    # Run simulation
    logging.info('Running simulation...')
    events_fs = filestore.FileStore(
        os.path.join(config['output']['temp_directory'], 'events'),
        context.Event, write=True)
    simulator.simulate(
        actors, defenders, config['defenders']['allow_defense'], events_fs,
        relationships, stix_vocab['threat-actor-sophistication'])
    # We don't know ahead of time how many moves will be made, so once the 
    # simulation is done, go back to the events and set to the correct day/time
    events = [events_fs.get(i[0]) for i in events_fs.query("SELECT id")]
    start = datetime.strptime(
        config["simulation"]['time_range'][0], '%Y-%m-%d')
    end = datetime.strptime(config["simulation"]['time_range'][1], '%Y-%m-%d')
    time_increment = (end - start)/len(events)
    newlist = sorted(events, key=lambda x: x.date)
    for e in newlist:
        e.date = start
        e.name = "Report_" + start.strftime("%Y%m%d_%H%M%S")
        events_fs.save(e, overwrite=True)
        start += time_increment

    # Create output files
    logging.info('Saving simulation output...')
    # Map
    try:
        map_matrix.plot_map(args.output_directory, **country_names)
        if 'html' in config['output']['output_types']:
            shutil.copy(
                os.path.join(args.output_directory, 'map.svg'),
                os.path.join(args.output_directory, 'html/'))
    except NameError:
        pass

    for ot in config['output']['output_types']:
        logging.debug('\t'+ot)
        path = args.output_directory + "/" + ot
        if ot == 'misp':
            output_dir.save_misp(path+'/events.json', events_fs)
        else:
            os.mkdir(path + '/reports/')
            events = [events_fs.get(i[0]) for i in events_fs.query("SELECT id")]
            events.sort(key=lambda x: x.name)
            for e in events:
                output_dir.output(ot+'/reports', e, ot)
        if ot == 'html':
            f = open(path+'/REPORT.html', 'r')
            template = f.read()
            f.close()
            ul_list = '<ul id="reports-list">'
            for e in events:
                f = open(path + '/reports/' + e.name + '.html', 'w')
                f.write(template.replace('REPORT', e.name))
                f.close()
                ul_list += f"<li><a href='reports/{e.name}.html'>{e.name}</a></li>"
            os.remove(path+'/REPORT.html')
            f = open(path + '/index.html', 'r')
            index = f.read()
            f.close()
            f = open(path + '/index.html', 'w')
            f.write(index.replace('<ul id="reports-list">', ul_list))
            f.close()

    # shutil.rmtree(config['output']['temp_directory'])

    logging.info('Done')


if __name__ == "__main__":
    main()
