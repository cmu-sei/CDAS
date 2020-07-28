# Cyber Decision Analysis Simulator - CDAS

(TODO) One Paragraph of project description goes here

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
Setting up outputs...
Overwrite the output folder (../output/)? (y/n)
$ y
Loading countries...
```

CDAS should finish with no errors and the results will be in a folder called cdas-output. Results will include
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