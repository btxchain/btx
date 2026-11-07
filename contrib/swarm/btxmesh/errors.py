"""Typed failures for the swarm reference package.

A MeshError names a stable code. It does not spend, and it does not mean the
monetary node failed.
"""


class MeshError(Exception):
    def __init__(self, code, detail=""):
        self.code = str(code)
        self.detail = str(detail) if detail else ""
        super().__init__(self.code if not self.detail else f"{self.code}: {self.detail}")


def require(cond, code, detail=""):
    if not cond:
        raise MeshError(code, detail)
