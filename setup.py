# coding: utf-8
"""
    snmptrap-gen
    Given a MIB name, generates and sends all traps with all OIDs populated with dummy values of the right type

    https://github.com/cisco-cx/snmptrap-gen
"""

from setuptools import setup, find_packages  # noqa: H301

NAME = "snmptrap-gen"
VERSION = "0.1.0"
# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

REQUIRES = [
    'docopt',
    'ply',
    'pprint',
    'pyasn1',
    'pycryptodomex',
    'pysmi',
    'pysnmp',
    'PyYAML',
    'six',
    'structlog',
]

setup(
    name=NAME,
    version=VERSION,
    description="SNMP Trap Generator",
    author_email="kusanagi-dev@cisco.com",
    url="https://github.com/cisco-cx/snmptrap-gen",
    keywords=["SNMP", "trap", "snmptrap-gen", "MIB", "generator"],
    install_requires=REQUIRES,
    include_package_data=True,
    long_description="""\
    snmptrap-gen SNMP Trap Generator (https://github.com/cisco-cx/snmptrap-gen)  # noqa: E501
    """,
    entry_points={'console_scripts': ['snmptrap-gen = snmptrap_gen.__init__:main']},
    packages=["snmptrap_gen"],
    package_dir={"": "src"},
)
