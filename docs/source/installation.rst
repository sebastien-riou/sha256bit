************
Installation
************
The package provides a command line tool and a Python3 API.

Command line tool
=================
Install with `pipx <https://pipx.pypa.io>`_, it puts the ``sha256bit``
command in its own isolated environment:

.. code-block:: bash

    pipx install sha256bit

The message is given as a hex string:

.. code-block:: console

    $ sha256bit 616263
    BA 78 16 BF 8F 01 CF EA 41 41 40 DE 5D AE 22 23 B0 03 61 A3 96 17 7A 9C B4 10 FF 61 F2 00 15 AD

If ``pipx`` is missing, on Debian/Ubuntu:

.. code-block:: bash

    sudo apt install pipx && pipx ensurepath

Python API
==========
Add it to your project with `pipenv <https://pipenv.pypa.io>`_:

.. code-block:: bash

    pipenv install sha256bit

If ``pipenv`` is missing:

.. code-block:: bash

    pipx install pipenv
