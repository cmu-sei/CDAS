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
from . import context, agents, simulator


def arguments():
    # Add and parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config", help="configuration file (json)")
    parser.add_argument(
        "-o", "--output", help="directory for storing results")
    parser.add_argument("--output-types",
        help="[\"pdf\", \"json\", \"stix\"]  ex. \"pdf,json\"")
    parser.add_argument(
        "--randomize-geopol", action='store_true',
        help="Generate random countries")
    parser.add_argument(
        "--num-countries", type=int,
        help="number of countries to generate (if geopol randomize is true)")
    parser.add_argument(
        "--country-data",
        help="directory with json files of country information")
    parser.add_argument("--overwrite-output", action='store_true')
    parser.add_argument("--overwrite-temp", action='store_true')

    args = parser.parse_args()
    if not args.config:
        args.config = pkg_resources.resource_filename(__name__, 'config.json')

    # Import configuration file
    with open(args.config, 'r') as f:
        config = json.load(f)
    f.close()

    # Set arguments to the specifications in the config file if not set at CL
    if not args.output:
        args.output = config['output_path']
    if not args.output_types:
        args.output_types = config['output_types']
    else:
        args.output_types = args.output_types.split(',')
    if not args.randomize_geopol:
        args.randomize_geopol = config["context"]['countries']['randomize']
    if not args.num_countries:
        args.num_countries = config["context"]['countries']['random_vars']['num_countries']
    if not args.country_data and args.randomize_geopol is False:
        args.country_data = pkg_resources.resource_filename(
            __name__,
            config["context"]["countries"]["non_random_vars"]["country_data"])

    args.random_geodata = pkg_resources.resource_filename(
        __name__, config["context"]["data_choices"])

    print("Configuration\n_____________")
    for arg in args.__dict__:
        print(f"    {arg}\t{args.__dict__[arg]}")
    print("")

    return(args, config)


def main(args, config):

    # Set up the Output directory
    if os.path.isdir(args.output):
        q = (
            f"Overwrite the output folder {os.getcwd() + '/' + args.output}? "
            f"(y/n) ")
    else:
        q = f"Output path {os.getcwd() + '/' + args.output} does not exist.\n\
            Create this directory? (y/n) "
    if not args.overwrite_output:
        answer = input(q)
    else:
        answer = 'y'
    if answer == 'n':
        sys.exit(f"CDAS exited without completing")
    elif answer == 'y':
        if os.path.isdir(args.output):
            for filename in os.listdir(args.output):
                file_path = os.path.join(args.output, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print('Failed to delete %s. %s' % (file_path, e))
        else:
            os.mkdir(args.output)
    else:
        overwrite = input(q)

    # Set up the STIX data stores
    # Check if it's okay to overwrite the contents of the temporary data store
    temp_path = pkg_resources.resource_filename(__name__, config['temp_path'])
    if os.path.isdir(temp_path):
        q = f"Overwrite temporary stix data folder ({temp_path})? (y/n) "
        overwrite = input(q)
        if overwrite == 'n':
            print(f"Rename the 'temp path' variable in config file and \
                restart the simulation.")
            sys.exit()
        elif overwrite == 'y':
            shutil.rmtree(temp_path)
            os.mkdir(temp_path)
        else:
            overwrite = input(q)
    else:
        os.mkdir(temp_path)
    fs_gen = FileSystemStore(temp_path)
    fs_real = FileSystemSource(
        pkg_resources.resource_filename(__name__, "assets/mitre_cti/"))

    # Load or create country data
    countries = []
    if args.randomize_geopol is True:
        print("Creating countries...")
        with open(args.random_geodata, encoding='utf-8') as f:
            context_options = json.load(f)  # seed file
        f.close()
        map_matrix = context.Map(args.num_countries)
        for c in range(0, args.num_countries):
            countries.append(context.Country(
                fs_gen, context_options, map_matrix.map))
        for c in countries:
            # This loop is used mainly to convert references to other countries
            # to the names of those countries instead of their ID numbers,
            # since, during the generation of each country it only has access
            # to map_matrix with ID numbers of the other countries

            # Convert the neighbors listed by id# to neighbor country names
            neighbors = {}
            for n in c.neighbors:
                n_name = next((x.name for x in countries if x.id == n), None)
                neighbors[n_name] = c.neighbors[n]
            c.neighbors = neighbors
            if len(c.neighbors) == 0:
                c.neighbors = "None (island nation)"

            # if country is a terrority, find its owner
            if c.government_type == "non-self-governing territory":
                gdps = [
                    (int(gdp.gdp[1:].replace(',', '')), gdp.name)
                    for gdp in countries]
                gdps.sort()
                # Territory owners are most likely to be high GDP countries
                # pick a random one from the top three GDP
                owner_name = np.random.choice([gdp[1] for gdp in gdps][-3:])
                if c.name in [gdp[1] for gdp in gdps][-3:]:
                    # if the territory itself is in the top three GDP, change
                    # its gov type to a republic instead of a territory
                    c.government_type = "federal parliamentary republic"
                else:
                    c.government_type += f" of {str(owner_name)}"
                    # update ethnic groups to include owner instead of random
                    owner = next(
                        (x.id for x in countries if x.name == owner_name),
                        None)
                    if str(owner) not in c.ethnic_groups:
                        egs = {}
                        for eg in c.ethnic_groups:
                            try:
                                int(eg)
                                if str(owner) not in egs:
                                    egs[str(owner)] = c.ethnic_groups[eg]
                                else:
                                    egs[eg] = c.ethnic_groups[eg]
                            except ValueError:
                                egs[eg] = c.ethnic_groups[eg]
                        c.ethnic_groups = egs
                    # update forces to include owner name if necessary
                    msf = c.military_and_security_forces
                    c.military_and_security_forces = msf.replace(
                        "[COUNTRY]", owner_name)
                    # update languages to include owner instead of random
                    if str(owner) not in c.languages:
                        langs = {}
                        for eg in c.languages:
                            try:
                                int(eg)
                                if str(owner) not in langs:
                                    langs[str(owner)] = c.languages[eg]
                                else:
                                    langs[eg] = c.languages[eg]
                            except ValueError:
                                langs[eg] = c.languages[eg]
                        c.languages = langs

            # Apply nationalities to ethnic groups listed by id#
            egs = {}
            for eg in c.ethnic_groups:
                try:
                    egs[next((
                            x.nationality for x in countries
                            if x.id == int(eg)),
                        None)] = c.ethnic_groups[eg]
                except ValueError:
                    egs[eg] = c.ethnic_groups[eg]
            c.ethnic_groups = egs

            # Convert languges listed by id# to country names
            egs = {}
            for eg in c.languages:
                try:
                    eg_name = next(
                        (x.name for x in countries if x.id == int(eg)),
                        None)
                    if eg_name.endswith(('a', 'e', 'i', 'o', 'u')):
                        eg_name += "nese"
                    else:
                        eg_name += 'ish'
                    egs[eg_name] = c.languages[eg]
                except ValueError:
                    egs[eg] = c.languages[eg]
            c.languages = egs
    else:
        # Using country data files instead of random generation
        print("Loading countries...")
        for fn in os.listdir(args.country_data):
            with open(args.country_data + fn, 'r') as f:
                country_data = json.load(f)
            f.close()
            countries.append(context.Country(fs_gen, **country_data))

    # Load or create actor data
    print("Creating threat actors...")
    with open(pkg_resources.resource_filename(
            __name__,
            "assets/stix_vocab.json"), encoding='utf-8') as json_file:
        stix_vocab = json.load(json_file)
    json_file.close()
    if config['agents']['randomize_threat_actors'] is True:
        with open(pkg_resources.resource_filename(
                __name__,
                config['agents']['random_variables']['actor_name_1']), encoding='utf-8') as f:
            adjectives = [line.rstrip() for line in f]
        f.close()
        with open(pkg_resources.resource_filename(
                __name__,
                config['agents']['random_variables']['actor_name_2']), encoding='utf-8') as f:
            nouns = [line.rstrip() for line in f]
        f.close()
        actors = 1
        while actors <= config['agents']['random_variables']['num_agents']:
            agents.create_threatactor(
                stix_vocab, nouns, adjectives, countries, fs_gen)
            actors += 1
    else:
        # no randomization - use provided data set
        raise NotImplementedError("Feature: Pre-defined threat actors not implemented yet")

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
    for c in countries:
        orgs = 0
        while orgs < config['agents']['org_variables']["orgs_per_country"]:
            agents.create_organization(
                stix_vocab, fs_gen, c.name, org_names, assessment)
            orgs += 1

    # Run simulation
    print('Running simulation...')
    start = datetime.strptime(
        config["simulation"]['time_range'][0], '%Y-%m-%d')
    end = datetime.strptime(config["simulation"]['time_range'][1], '%Y-%m-%d')
    td = end - start
    actors = fs_gen.query(Filter("type", "=", "threat-actor"))
    orgs = fs_gen.query([
        Filter("type", "=", "identity"),
        Filter("identity_class", "=", "organization")])
    tools = fs_real.query(Filter('type', '=', 'tool'))
    malwares = fs_real.query(Filter('type','=','malware'))
    for r in range(1, int(config["simulation"]['number_of_rounds'])+1):
        print(f'\tRound {r}')
        simulator.simulate(
            actors, orgs, tools, malwares, fs_gen, start,
            td.days/(config["simulation"]['number_of_rounds']*len(actors)))
        start += timedelta(
            days=td.days/config["simulation"]['number_of_rounds'])

    # Create output files
    print('Saving output...')
    # Map
    country_names = {}
    for country in countries:
        country_names[str(country.id)] = country.name
    try:
        map_matrix.plot_map(args.output, **country_names)
    except NameError:
        pass

    for ot in args.output_types:
        print(f'\t{ot}')
        if ot == "stix":
            shutil.copytree(temp_path, args.output+"/stix")
        else:
            if not os.path.isdir(args.output + '/countries/'):
                os.mkdir(args.output + '/countries/')
                os.mkdir(args.output + '/actors/')
                os.mkdir(args.output + '/reports/')
            for country in countries:
                country.save(args.output + '/countries/', ot)
            agents.save(args.output + '/actors/', ot, fs_gen, fs_real)
            events = fs_gen.query(Filter("type", "=", "sighting"))
            for e in events:
                simulator.save(
                    e, fs_gen, fs_real, args.output + '/reports/', ot)

    shutil.rmtree(temp_path)

    print('Done')


if __name__ == "__main__":
    args, config = arguments()
    main(args, config)
