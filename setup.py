import pathlib
from setuptools import setup

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

# This call to setup() does all the work
setup(
    name="cdas",
    version="0.0.1",
    description="Cybersecurity Decision Analysis Simulator",
    long_description=README,
    long_description_content_type="text/markdown",
    url="",
    author="",
    author_email="",
    license="",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    packages=["cdas"],
    include_package_data=True,
    install_requires=["numpy","reportlab","drawSVG"],
    entry_points={
        "console_scripts": [
            "cdas=cdas.__main__",
        ]
    },
)