# sha256bit
SHA256 with bit granularity for message input length.

## Usage

    >>> from sha256bit import sha256bit
    >>> sha256bit(inbits,bitlen=len(inbits)).hexdigest()
    'bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375'
    
## Build the package
````
python3 -m build
````

## Test
Tests can run without creating/installing the package:
````
python3 -m test.test
````
