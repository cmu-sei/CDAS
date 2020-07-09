import json
import numpy as np
import os
import shutil
import sys
import pkg_resources
import argparse
# Import custom modules
from . import context

# Set global variables
CONFIG_FILE = pkg_resources.resource_filename(__name__, 'config.json')

def arguments():
    # Add and parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-o","--output",
        help="directory for storing results")
    parser.add_argument("-c","--config",
        help="configuration file (json)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--num-countries", type=int,
        help="number of countries to generate (if context randomize is true)")
    group.add_argument("--country-data",
        help="directory with json files of country information")
    
    args = parser.parse_args()
    if not args.config:
        args.config = pkg_resources.resource_filename(__name__, 'config.json')

    return(args)


def main(args):

    # Import configuration file
    with open(args.config, 'r') as f:
        config = json.load(f)
    f.close()

    # Set arguments
    if not args.output: args.output = config['output_path']
    if not args.num_countries:
        args.num_countries = config["context"]['countries']['random_vars']['num_countries']
    if not args.country_data:
        args.country_data = config["context"]["countries"]["non_random_vars"]["country_data"]

    print(args)

    # Set up the Output directory
    if os.path.isdir(args.output):
        if os.listdir(args.output):
            q = f"Overwrite the output folder {os.getcwd() + '/' + args.output}? (y/n) "
            overwrite = input(q)
            if overwrite == 'n':
                sys.exit(f"CDAS exited without completing")
            elif overwrite == 'y':
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
                overwrite = input(q)
        os.mkdir(args.output + '/countries/')
    else:
        q = f"Output path {os.getcwd() + '/' + args.output} does not exist.\n\
            Create this directory? (y/n) "
        answer = input(q)
        if answer  == "y":
            os.mkdir(args.output)
            os.mkdir(args.output + '/countries/')
        elif answer == "n":
            sys.exit(f"CDAS exited without completing")
        else:
            answer = input(q)

    # Load or create country data
    c_cf = config["context"]
    countries = []
    if c_cf["countries"]["randomize"] is True:
        with open(pkg_resources.resource_filename(
                __name__, c_cf["data_choices"])) as f:
            context_options = json.load(f)  # seed file
        f.close()
        map_matrix = context.Map(args.num_countries)
        for c in range(0, args.num_countries):
            countries.append(context.Country(context_options, map_matrix.map))
        for c in countries:
            # This loop is used mainly to convert references to other countries
            # to the names of those countries instead of their ID numbers, 
            # since, during the generation of each country it only has access to
            # map_matrix with ID numbers of the other countries

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
                        (x.id for x in countries if x.name == owner_name), None)
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
                    egs[next((x.nationality for x in countries if x.id == int(eg)),
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

            # Ensure country codes are not duplicated
            country_codes = [x.internet_country_code for x in countries]
            if country_codes.count(c.internet_country_code) > 1:
                i = 1
                new_cc = "."+c.name[i:i+2]
                while new_cc in country_codes:
                    i += 1
                    new_cc = "."+c.name[i:i+2]
                c.internet_country_code = new_cc
    else:
        # Using country data files instead of random generation
        for fn in os.listdir(args.country_data):
            with open(args.country_data + fn, 'r') as f:
                country_data = json.load(f)
            f.close()
            countries.append(context.Country(**country_data))

    # Create output files
    # Map
    country_names = {}
    for country in countries:
        country_names[str(country.id)] = country.name
    try:
        map_matrix.plot_map(args.output, **country_names)
    except NameError:
        pass
    # Countries
    for country in countries:
        country.save(args.output + '/countries/', config['output_type'])

if __name__ == "__main__":
    args = arguments()
    main(args)