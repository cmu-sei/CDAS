# Examples and Use Cases

The following are examples of how to use different features in CDAS and possible configurations for various use cases.

Using the Features

- [Generating fake actors with pre-set custom countries](#1.1)
- [Customizing data after generation](#1.2)

Use Cases

- ...

## Using the Features

### <a name="1.1"></a>Generating fake actors with pre-set custom countries

You can take advantage of CDAS's ability to ingest real-world country data to ingest custom-created country data instead.

Your country data must be json formatted files similar to the CIA world factbook data files included with CDAS (or similar to the json country output from randomly generated countries). Not all fields are required, and CDAS can incorporate extra fields in the country data. However, CDAS will error if it does not find a subset of fields in the given files, such as the "name" field. 

1. Set the country randomization in the config file to false (```["context"]["countries"]["randomize"]```)

2. Place your country data files in a folder (ex. custom_data/countries/)

3. Set the country data path to your folder with the custom country data (```["context"]["countries"]["non_random_vars"]["country_data"]```)

    Sample configuration:
    ```
    ...
    "context": {
       "countries": {
           "randomize": false,
           "random_vars": {
               "num_countries": 50
           },
           "non_random_vars": {
                "country_data": "/Users/player_1/custom_data/countries/"
           }
       },
       "data_choices": "data/geopol_data.json"
    },
    ...
    ```

4. Run CDAS
    ```
    $ python3 -m cdas
    ```

### <a name="1.2"></a>Customizing data after generation

You can use CDAS to do 95% of the scenario generation work for you and then make minor tweaks to the generated documentation to customize it for your scenario, saving a tremendous amount of time on scenario generation. The easiest way to do this is to set the CDAS configuration file as close to your scenario as possible, run CDAS with a json output type, then make adjustments to the json files as necessary. 

For example, you have a scenario in which you want to use real country data and fake APTs, but you have a requirement to include a specific international dispute between Country A and Country B, as well as a requirement to match one of the fake APTs to Country B. Your approach would be the following. 

1. Configure CDAS
    - Set ```["agents"]["randomize_threat_actors"]``` to true
    - Set ```["context"]["countries"]["randomize"]``` to false
    - Set the output type ```"output_types"``` to json ```["json"]```
    - The variable for the country data ```["context"]["countries"]["non_random_vars"]["country_data"]``` should be set to "cia_world_factbook" or a different data set of your choice
    - Check the configuration file for other variables relevant to your scenario

    A sample configuration file might look like this:
    ```
    {
        "agents": {
            "randomize_threat_actors": true,
            "random_variables": {
                "actor_name_1": "data/personality_traits.txt",
                "actor_name_2": "data/disney_names.txt",
                "num_agents": 5
            },
            "non_random_vars": {
                "apt_data": "mitre_cti"
            },
            "org_variables": {
                "orgs_per_country": 1,
                "org_names": "data/organization_names.txt"
            }
        },
        "context": {
        "countries": {
            "randomize": false,
            "random_vars": {
                "num_countries": 50
            },
            "non_random_vars": {
                    "country_data": "cia_world_factbook"
            }
        },
        "data_choices": "data/geopol_data.json"
        },
        "assets": {

        },
        "simulation": {
            "number_of_rounds": 5,
            "time_range": [
                "2017-08-01",
                "2020-08-01"
            ]
        },
        "output_path": "cdas-output",
        "output_type_opts": [
            "json",
            "pdf",
            "stix"
        ],
        "output_types": ["json"],
        "temp_path": "cdas-temp"
    }
    ```

2. Run CDAS

    ```
    $ python3 -m cdas
    ```

3. Open the json files for Country A and Country B and make the necessary changes directly in the json file to the "international disputes" section.

4. Check the actor files to determine whether an actor has already been assigned to Country B. If not, choose an actor file and change its attribution to Country B.

5. You may want to check that the reports associated with the actor you chose make sense given the change in attribution. Make adjustments as necessary

## Use Cases

...