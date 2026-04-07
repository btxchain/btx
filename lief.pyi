from typing import Any


# The upstream `lief` package has shipped incompatible typing surfaces across
# releases (and some versions have no usable stubs at all). For repository
# linting we only need a stable import/type-check contract, so model LIEF as
# dynamic and leave runtime behavior to the actual installed package.
def __getattr__(name: str) -> Any: ...


def parse(*args: Any, **kwargs: Any) -> Any: ...
