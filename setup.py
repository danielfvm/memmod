# -*- coding: utf-8 -*-
from setuptools import setup

packages = \
['memmod', 'memmod.scripts']

package_data = \
{'': ['*']}

install_requires = \
['capstone>=15.0.0,<16.0.0', 'elftools>=0.28,<0.29']

setup_kwargs = {
    'name': 'memmod',
    'version': '0.0.1',
    'description': "A library to modify another program's memory.",
    'long_description': None,
    'author': 'danielfvm',
    'author_email': 'ds@xxxmail.eu',
    'maintainer': None,
    'maintainer_email': None,
    'url': None,
    'packages': packages,
    'package_data': package_data,
    'install_requires': install_requires,
}
from build import *
build(setup_kwargs)

setup(**setup_kwargs)
