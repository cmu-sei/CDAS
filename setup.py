import pathlib
from setuptools import setup

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text(encoding="utf8")
LICENSE = (HERE / "LICENSE.md").read_text(encoding="utf8")

setup(
    name="cdas",
    version="0.0.2",
    description="Cybersecurity Decision Analysis Simulator",
    long_description=README,
    long_description_content_type="text/markdown",
    license=LICENSE,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    packages=["cdas"],
    include_package_data=True,
    package_data={
        'cdas': [
            'data/*',
            'data/cia_world_factbook/*',
            'data/asns/*'
            'assets/*',
            'assets/html_templates/*'
            'assets/mitre_cti/*',
            'assets/mitre_cti/attack-patterns/*',
            'assets/mitre_cti/threat-actors/*',
            'assets/mitre_cti/malware/*',
            'assets/mitre_cti/tools/*'
        ]
    },
    install_requires=["numpy", "reportlab", "drawSVG"],
    entry_points={
        "console_scripts": [
            "cdas=cdas.__main__:main",
        ]
    },
)
