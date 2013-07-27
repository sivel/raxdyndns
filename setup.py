#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2013 Matt Martz
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from setuptools import setup, find_packages

dependencies = ['requests', 'pyrax>=1.4.5', 'keyring', 'PyYAML']

setup(
    name='raxdyndns',
    description='Dynamic DNS Update utility using Rackspace Cloud DNS',
    keywords='rackspace cloud dns dyndns',
    version='0.0.2',
    author='Matt Martz',
    author_email='matt@sivel.net',
    install_requires=dependencies,
    entry_points={'console_scripts':
                  ['raxdyndns=raxdyndns:main']},
    packages=find_packages(exclude=['vagrant', 'tests', 'examples', 'doc']),
    license='Apache License (2.0)',
    classifiers=["Programming Language :: Python"],
    url='https://github.com/sivel/raxdyndns',
)
