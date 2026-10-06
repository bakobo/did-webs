"""The upstream-keripy oracle's glue: a venv provisioner and an in-venv verification script.

Decision ``0plkq8s8``: the v2 target is what stock WebOfTrust/keripy main accepts, not the
bakobo fork this project's own venv runs. Every v2 ``keri.cesr`` didwebs emits is therefore
handed to upstream keripy, installed in its own venv, and vetted there by
``tests/test_upstream_v2.py``.

Nothing here is imported by ``src/didwebs``. See ``keripy_venv.py`` for the upstream pin and
``vet_stream.py`` for the script that runs *inside* that venv.
"""
