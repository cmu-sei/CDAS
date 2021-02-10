# Cyber Decision Analysis Simulator - CDAS

![CDAS Logo](cdas/assets/images/CDAS.png)

## Overview

This program generates cyber attack scenarios for use in cyber training exercises, red team planning, blue team planning, automated attack execution, and cybersecurity policy analysis. The current version generates documentation for these scenarios in the form of cyber incident reports and supporting contextual information (information on countries and threat actors). Scenarios can be based on real countries and geopolitical context, or have this context generated psuedo-randomly. Scenarios can use real APTs or have them generated pseudo-randomly to match the geopolitical context. Simulated cyber events are then generated based on APT motivation and organization vulnerability.

Future versions will include fine-grained ability to control detailed aspects of the simulation, improved logic for APT and event generation, and a policy analysis capability allowing decision makers to compare risk reduction or outcome improvements across different policy simulations.

## Features

- [x] Country and geopolitical context generation
- [x] APT generation
- [x] Cyber event generation (incidents, attacks, intelligence)
- [x] Output formats: PDF, JSON, MISP and/or HTML


## License

Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgements

* Default country information is pulled from the CIA World Factbook site (https://www.cia.gov/library/publications/the-world-factbook/)
* Default intrusion set information for CDAS comes from the [Mitre Cyber Threat Intelligence repository](https://github.com/mitre/cti).