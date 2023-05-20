# sha256bit
Pure python implementation of SHA256 with features which are often lacking:
- bit granularity for message input length
- import/export API to "persist" the state in the middle of a hash computation

## Installation

    python3 -m pip install sha256bit

## Usage

### One liner 

    >>> from sha256bit import sha256bit
    >>> sha256bit("abc".encode()).hexdigest()
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

### Bit length capability

    >>> from sha256bit import sha256bit
    >>> sha256bit(b'\x00',bitlen=1).hexdigest()
    'bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375'

### Import/export

    >>> from sha256bit import sha256bit
    >>> h1 = sha256bit("a".encode())
    >>> state = h1.export_state()
    >>> h2 = sha256bit.import_state(state)
    >>> h2.update("bc".encode())
    >>> h2.hexdigest()
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

## Build the package
````
python3 -m build
````

## Test
Tests can run without creating/installing the package:
````
python3 -m test.test
````
