# sha256bit


| | |
| --- | --- |
| CI/CD | [![CI - Test](https://github.com/sebastien-riou/sha256bit/actions/workflows/test.yml/badge.svg)](https://github.com/sebastien-riou/sha256bit/actions/workflows/test.yml) [![CD - Build](https://github.com/sebastien-riou/sha256bit/actions/workflows/build.yml/badge.svg)](https://github.com/sebastien-riou/sha256bit/actions/workflows/build.yml) |
| Package | [![PyPI - Version](https://img.shields.io/pypi/v/sha256bit.svg?logo=pypi&label=PyPI&logoColor=gold)](https://pypi.org/project/sha256bits/) [![PyPI - Python Version](https://img.shields.io/pypi/pyversions/sha256bit.svg?logo=python&label=Python&logoColor=gold)](https://pypi.org/project/sha256bit/) |
| Meta | [![Hatch project](https://img.shields.io/badge/%F0%9F%A5%9A-Hatch-4051b5.svg)](https://github.com/pypa/hatch)  [![code style - black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![types - Mypy](https://img.shields.io/badge/types-Mypy-blue.svg)](https://github.com/ambv/black) [![License - apache-2.0](https://img.shields.io/badge/license-apache--2.0-blue)](https://spdx.org/licenses/) |


Pure python implementation of SHA256 with features which are often lacking:
- bit granularity for message input length
- import/export API to "persist" the state in the middle of a hash computation

## Installation

    python3 -m pip install sha256bit

## Usage

### One liner 

    >>> from sha256bit import Sha256bit
    >>> Sha256bit("abc".encode()).hexdigest()
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

### Bit length capability

    >>> from sha256bit import Sha256bit
    >>> Sha256bit(b'\x00',bitlen=1).hexdigest()
    'bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375'

### Import/export

    >>> from sha256bit import Sha256bit
    >>> h1 = Sha256bit("a".encode())
    >>> state = h1.export_state()
    >>> h2 = Sha256bit.import_state(state)
    >>> h2.update("bc".encode())
    >>> h2.hexdigest()
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

## Test with `pytest`

    pytest-3

## Test without `pytest`
Tests can run without creating/installing the package:

    python3 -m test.test


you can also run each test separately:

    python3 -m test.test_api
    python3 -m test.test_cavp
    python3 -m test.test_hardcoded
    python3 -m test.test_vs_hashlib

## Build the package
Build is done using `hatchling`. The script `build` allows to build for different version of python3:

    ./build python3.9


## Create a new version
Version is managed by `hatch-vcs`, you just need to create a tag in github. 