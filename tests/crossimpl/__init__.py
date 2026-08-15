"""The cross-implementation oracle's glue: a resolver-venv provisioner, an in-venv runner
script, and a field-level document comparator (docs/design.md, ``Test strategy 1``).

Nothing here is imported by ``src/didwebs`` — this package exists only for
``tests/test_crossimpl.py`` and is not part of the product. See ``resolver_venv.py`` for the
GLEIF resolver pin, ``runner.py`` for how a stream reaches the resolver's own Python 3.13
process, ``resolver_runner.py`` for the script that runs *inside* that process, and
``compare.py`` for the documented field-level intersection.
"""
