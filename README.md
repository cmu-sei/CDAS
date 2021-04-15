# Cyber Decision Analysis Simulator - CDAS

![CDAS Logo](cdas/assets/images/CDAS.png)

## Overview

This program generates cyber attack scenarios for use in cyber training exercises, red team planning, blue team planning, automated attack execution, and cybersecurity policy analysis. CDAS generates documentation for these scenarios in the form of cyber incident reports and supporting contextual information (information on countries and threat actors). Scenarios can be based on real countries and geopolitical context, or have this context generated psuedo-randomly. Scenarios can use real APTs or have them generated pseudo-randomly to match the geopolitical context. Simulated cyber events are then generated based on APT motivation and organization vulnerability.

## Features

- [x] Country and geopolitical context generation
- [x] APT generation
- [x] Cyber event generation (incidents, attacks, intelligence)
- [x] Output formats: PDF, JSON, MISP and/or HTML

### ToDo
- [ ] Country relationship details
- [ ] Detailed representation of defender networks (asset improvement)
- [ ] Visualization of relationships between data points
- [ ] Improved world map generation
- [ ] "web feeds" of intelligence/events (ex. news reports, dark web posts, etc.)

## Components

- Agents: Threat actors, defenders (companies)
    - Friendly, enemy, and neutral players in the simulation
- Assets: Cyber infrastructure
    - Networks, software, hardware, configurations, and vulnerabilities
- Context: Geopolitical context
    - Countries, country attributes, and relationships with other countries which drive agent decision making
- Simulation
    - Decision parameters, simulation parameters, and output/formatting controls

## Getting Started

These instructions will get you a copy of the project up and running on your local machine. For detailed instructions on how to configure and use CDAS, see the [User Guide](UserGuide.md).

### Prerequisites

CDAS installs the following packages and their dependencies upon setup:

```
numpy
reportlab
drawSVG
cyberdem
```

### Installing

1. Download CDAS and unzip the download folder
2. From within the top-level cdas folder (where setup.py is located) run

```
$ pip3 install .
```

3. To test that CDAS is installed properly run

```
$ python3 -m cdas -c sample_configs/randomize_all_small_pdf.json -v
Setting up directories...
Creating fake countries...
Creating fake threat actors...
Running simulation...
        Round 1
        Round 2
        Round 3
        Round 4
        Round 5
Saving output...
        pdf
Done
```

CDAS should finish with no errors and the results will be in a folder called cdas-output. Results will include
- SVG map of countries
- A "pdf" folder containing
    - 'actors' folder containing PDF files with threat actor descriptions
    - 'countries' folder containing PDF files with country attributes
    - 'reports' folder containing PDF files with event reports
    - 'defenders' folder containing PDF files with organization descriptions

## Configuration

CDAS is configured via a required json file. You will find several sample configuration files in the [sample_configs](sample_configs) folder. Users can change variables related to geopolitical context generation, asset generation, agent generation, whether to randomize or use real world data, and more. See the [User Guide](UserGuide.md) for further instructions.

Additionally, there are three available command line flags: the required config-file, and the optional input and output directories. See the help menu for information on available flags.

```
$ python3 -m cdas -h
usage: __main__.py [-h] -c CONFIG_FILE [-i INPUT_DIRECTORY] [-o OUTPUT_DIRECTORY] [--verbose]

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        configuration file (json)
  -i INPUT_DIRECTORY, --input-directory INPUT_DIRECTORY
                        directory for specifying custom data
  -o OUTPUT_DIRECTORY, --output-directory OUTPUT_DIRECTORY
                        directory for storing results
  --verbose, -v         v for basic status, vv for detailed status
```

## Simulation Details

### Model

- *type* - the player's prioritization of the security triad (Confidentiality, Integrity, Availability). For example, a defender listed as type, "CIA", prioritizes confidentiality the most and availability the least. An attacker listed as, "CIA", prioritizes espionage the highest (breaking confidentiality) and disrpution/denial (breaking availability) the least.

## License

Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgements

* Default country information is pulled from the CIA World Factbook site (https://www.cia.gov/library/publications/the-world-factbook/)
* Default intrusion set information for CDAS comes from the [Mitre Cyber Threat Intelligence repository](https://github.com/mitre/cti).