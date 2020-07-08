# Cyber Decision Analysis Simulator - CDAS

(TODO) One Paragraph of project description goes here

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

Before installing CDAS you will need the following packages:

```
numpy
reportlab
drawSVG
```

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

CDAS should finish with no errors and the results will be in your output folder.

## Configuration

CDAS is configured via the config.json file in the cdas module folder. See [Config.md](Config.md) for further instructions.

## License

(TODO) Licensing...

## Acknowledgments

* Structured Threat Information Expression (STIX™) (https://oasis-open.github.io/cti-documentation/stix/intro)
* Mitre ATT&CK (https://attack.mitre.org/)