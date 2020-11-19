# -*- coding: utf-8 -*-
# Copyright 2020 Max Kratz
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This file is used as a setup script for the package.
"""

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="matrix-synapse-saml-mapper",
    version="0.0.5",
    author="Maximilian Kratz",
    author_email="mkratz@fs-etit.de",
    description="Custom SAML mapping provider for synapse installations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/maxkratz/matrix-synapse-saml-mapper",
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
