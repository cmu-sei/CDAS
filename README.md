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
python-stix
```

You may also want to install ```libcairo2```. Optional, but you will receive errors when running CDAS without it.

### Installing

From the top-level cdas folder

```
$ pip3 install .
```

Create an output directory in the location you wish to output results from the simulator. For example

```
$ cd ~/Desktop 
$ mkdir output
```

To test that CDAS is installed properly run

```
# from ~/Desktop 

$ python -m cdas
Setting up outputs...
Overwrite the output folder (../output/)? (y/n)
$ y
Loading countries...
```

CDAS should finish with no errors and the results will be in your output folder. Results will include
- SVG map of countries (if context was randomized)
- Countries folder containing files with country attributes

## Configuration

CDAS is configured via the config.json file in the cdas module folder. Users can change variables related to geopolitical context generation, asset generation, agent generation, whether to randomize or use real world data, and more. See [Config.md](Config.md) for further instructions.

## License

Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgements

* CIA World Factbook (https://www.cia.gov/library/publications/the-world-factbook/)