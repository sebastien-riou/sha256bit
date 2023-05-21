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





