# Cyber Decision Analysis Simulator - CDAS

## Overview

This program generates cyber attack scenarios for use in cyber training exercises, red team planning, blue team planning, automated attack execution, and cybersecurity policy analysis. The current version generates documentation for these scenarios in the form of cyber incident reports and supporting contextual information (information on countries and threat actors). Scenarios can be based on real countries and geopolitical context, or have this context generated psuedo-randomly. Scenarios can use real APTs or have them generated pseudo-randomly to match the geopolitical context. 

Future versions will include fine-grained ability to control detailed aspects of the simulation, improved logic for APT and event generation, and a policy analysis capability allowing decision makers to compare risk reduction or outcome improvements across different policy simulations.

## Features

- [x] Country and geopolitical context generation
- [x] APT generation
- [x] Cyber event generation (incidents, attacks, intelligence)
- [x] Output formats: PDF, JSON, and/or STIX

### ToDo
- [ ] Output formats: HTML, SQL dump
- [ ] Visualization of relationships between data points
- [ ] Improved world map generation
- [ ] "web feeds" of intelligence/events (ex. news reports, dark web posts, etc.)

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

CDAS installs the following packages and their dependencies upon setup:

```
numpy
reportlab
drawSVG
stix2
```

You may also want to install ```libcairo2```. Optional, but you will receive errors when running CDAS without it.

### Installing

1. Download CDAS and unzip the download folder
2. From within the top-level cdas folder (where setup.py is located) run

```
$ pip3 install .
```

3. To test that CDAS is installed properly run

```
$ python -m cdas
Output path ..\cdas-output does not exist.
            Create this directory? (y/n)
$ y
Creating countries...
Creating threat actors...
Creating organizations...
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

CDAS should finish with no errors (you will get warnings about libcairo2 if you did not install that) and the results will be in a folder called cdas-output. Results will include
- SVG map of countries
- 'actors' folder containing PDF files with threat actor descriptions
- 'countries' folder containing PDF files with country attributes
- 'reports' folder containing PDF files with event reports

## Configuration

CDAS is configured via the config.json file in the cdas python module folder. Users can change variables related to geopolitical context generation, asset generation, agent generation, whether to randomize or use real world data, and more. See [Config.md](Config.md) for further instructions.

Many of the variables in the configuration file can be changed with command line flags. See the help menu for information on available flags.

```
$ python -m cdas -h
```

## License

Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgements

* CIA World Factbook (https://www.cia.gov/library/publications/the-world-factbook/)