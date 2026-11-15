"""Stable machine-readable errors. Do not expose secrets in exception text."""
class SwapError(Exception):
    def __init__(self, code: str, message: str):
        self.code, self.message = code, message
        super().__init__(f"{code}: {message}")
    def as_dict(self):
        return {"code": self.code, "message": self.message}

def require(condition, code, message):
    if not condition:
        raise SwapError(code, message)
