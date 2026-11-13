# Embedded SwapNet implementation

The native build freezes `swapnet/*.py` into the node and runs `swapnet.embedded.Host` on the dedicated C++ worker thread. This directory is not a separately launched production daemon. The Python package is also importable for local testing and qualification tools.

```sh
python3 -m pip install -e '.[test]'
python3 -m pytest tests -q
```

Install dependencies in the same interpreter environment selected by the native CMake build. Native builds use isolated imports and intentionally do not honor a developer's arbitrary PYTHONPATH. See the main package entry point and `doc/swapnet/` for integration, operation and qualification.

`service.py` retains tested catalog/quote helpers and legacy component APIs; production execution enters `application.py` and `coordinator.py`, not the earlier standalone observer. That obsolete entry point is retained only under package provenance.
