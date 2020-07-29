# CDAS Configuration File

The main configuration file for cdas, ```config.json```, is located in the main folder of the cdas package in your python site packages. 

The config file controls whether the data used in the simulator is generated randomly or pulled from a file. It specifies which files to use for data sets and randomization seeding. 

Many of the variables in the configuration file can be changed with command line flags. See the help menu for information on available flags.

```
$ python -m cdas -h
```

The CDAS configuration file has five sections: Context, Assets, Agents, Simulation, and output variables. 

## Configuration

### Context Configuration

This section defines the configuration for the geopolitical context component of the simulator.

The context section of the configuration file looks like this:

```
"context" : {
    "countries" : {
        "randomize" : true,
        "random_vars" : {
            "num_countries" : 5
        },
        "non_random_vars" : {
            "country_data" : "./data/cia_world_factbook/"
        }
    },
    "data_choices" : "./data/geopol_data.json"
   }
```

- countries
    - randomize - if true, the simulator generates randomized countries and associated attributes; if false, the simulator imports country data from files provided in the country_data key
    - random_vars
        - num_countries - the nuber of countries for which the simulator should create fake data; used if the "randomize" variable is true
    - non_random_vars
        - country_data - directory containing json files with country data (one file per country); used if the "randomize" variable is false
- data_choices - seed file for context randomization. Contains options for items such as colors, animals, agriculture, climate, etc.

### Asset Configuration
<TODO>

### Agent Configuration
<TODO>

### Simulation Configuration
<TODO>

### Output Configuration
<TODO>

```
   "output_path" : "output/",
   "output_type_opts" : ["json","pdf"],
   "output_type" : "pdf",
   "temp_path" : "temp"
```

## Example 1

## License

Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](LICENSE.md) file for details.