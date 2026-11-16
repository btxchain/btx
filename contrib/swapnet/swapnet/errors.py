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

class RPCConnectionRefused(SwapError):
    """Internal transport classification; retain the public unavailable code."""
    def __init__(self):
        super().__init__("RPC_UNAVAILABLE", "Local chain client connection refused")

class RPCTransportTimeout(SwapError):
    """Internal open/read timeout; not permission to bypass recovery checks."""
    def __init__(self):
        super().__init__("RPC_UNAVAILABLE", "Local chain client request timed out")
