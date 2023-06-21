****************
Python3 examples
****************

One liner
=========

.. testcode::

	from sha256bit import Sha256bit
	print(Sha256bit("abc".encode()).hexdigest())

.. testoutput::

    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad


Bit length capability
=====================

One liner
----------

.. testcode::

    from sha256bit import Sha256bit
    print(Sha256bit(b'\x00',bitlen=1).hexdigest())
    
.. testoutput::

    bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375

Update / digest
-----------------

.. testcode::

    from sha256bit import Sha256bit
    h = Sha256bit()
    h.update(b'\x00',bitlen=1)
    print(h.hexdigest())
    
.. testoutput::

    bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375

Import / export
=====================

.. testcode::

    from sha256bit import Sha256bit
    h1 = Sha256bit("a".encode())
    state = h1.export_state()
    h2 = Sha256bit.import_state(state)
    h2.update("bc".encode())
    print(h2.hexdigest())

.. testoutput::

    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

Dumping intermediate values
============================
This is useful to people working on their own implemention of SHA256.
The verbosity is controlled by the logging level. 

- Use 'INFO' to dump block level information
- Use 'DEBUG' to dump all intermediate values

.. testsetup:: ['dump']

    import logging    
    class PrintHandler(logging.StreamHandler):
        def emit(self, record):
            msg = self.format(record)
            print(msg)
            self.flush()
    print_handler = PrintHandler()
    logger = logging.getLogger()
    logger.setLevel(logging.INFO) 
    logger.addHandler(print_handler)
    

.. testcode:: ['dump']

    import logging  
    from sha256bit import Sha256bit
    logging.basicConfig(format='%(message)s', level='INFO')
    print(Sha256bit("abc".encode()).hexdigest())

.. testoutput:: ['dump']

    bitlen: 24
    state:  6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A 51 0E 52 7F 9B 05 68 8C 1F 83 D9 AB 5B E0 CD 19
    block:  61 62 63 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 18
    digest: BA 78 16 BF 8F 01 CF EA 41 41 40 DE 5D AE 22 23 B0 03 61 A3 96 17 7A 9C B4 10 FF 61 F2 00 15 AD
    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad


.. testcode:: ['dump']
    :skipif: True

    import logging
    from sha256bit import Sha256bit
    logging.basicConfig(format='%(message)s', level='INFO')
    message = Utils.ba('E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6 E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4 3E 41 98 3F 5D 4C 94 56 5F E4 46 3C')
    h1 = Sha256bit(message[0:64])
    state = h1.export_state()
    h2 = Sha256bit.import_state(state)
    h2.update(message[64:])
    print(h2.hexdigest())
    
.. testoutput:: ['dump']
    :skipif: True

    state:  6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A 51 0E 52 7F 9B 05 68 8C 1F 83 D9 AB 5B E0 CD 19
    block:  E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6 E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4 3E 41 98 3F 5D 4C 94 56
    exporting current state:
      bitlen = 512
      state:  9F BF AC E6 3F D1 4E 52 19 13 7C 71 F6 23 23 5F 63 2B 67 BB 02 7A 79 F3 90 E9 80 96 02 BE 40 E2
      cache:  
    importing current state:
      bitlen = 512
      state:  9F BF AC E6 3F D1 4E 52 19 13 7C 71 F6 23 23 5F 63 2B 67 BB 02 7A 79 F3 90 E9 80 96 02 BE 40 E2
      cache:  
    bitlen: 544
    state:  9F BF AC E6 3F D1 4E 52 19 13 7C 71 F6 23 23 5F 63 2B 67 BB 02 7A 79 F3 90 E9 80 96 02 BE 40 E2
    block:  5F E4 46 3C 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 20
    digest: CC 87 D0 D0 0E E7 4D 5B 2F 47 17 77 70 FF 78 4F 5A 72 B1 89 33 14 65 33 FB C1 BC AC 6C 70 07 B9
    cc87d0d00ee74d5b2f47177770ff784f5a72b18933146533fbc1bcac6c7007b9

