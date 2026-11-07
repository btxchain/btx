import contextlib
import os
import sqlite3
import tempfile
import threading
from pathlib import Path
from .errors import require


def private_dir(path: Path):
    path = Path(os.path.abspath(path))
    # Never chmod through a symlink supplied as a directory or ancestor.
    for component in (path, *path.parents):
        require(not component.is_symlink(), "SYMLINK")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if hasattr(os, "geteuid"):
        require(path.stat().st_uid == os.geteuid(), "DIRECTORY_OWNER")
    os.chmod(path, 0o700)
    return path


def atomic_write(path: Path, data: bytes, mode: int = 0o600):
    private_dir(path.parent)
    require(not path.is_symlink(), "SYMLINK")
    fd, name = tempfile.mkstemp(prefix=".staging-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(name, path)
        if os.name == "posix":
            dfd = os.open(path.parent, os.O_DIRECTORY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
    finally:
        if os.path.exists(name): os.unlink(name)


class Database:
    """Serialized local connection; all state transitions use explicit transactions."""
    def __init__(self, path):
        path = Path(path); private_dir(path.parent)
        require(not path.is_symlink(), "SYMLINK")
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=5000")
        os.chmod(path, 0o600)
    @contextlib.contextmanager
    def tx(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
    def close(self):
        with self.lock: self.db.close()


class ProcessLock:
    def __init__(self,path:Path):
        import fcntl
        private_dir(path.parent);require(not path.is_symlink(),"LOCK_SYMLINK")
        self.file=path.open("a+b");os.chmod(path,0o600)
        try:fcntl.flock(self.file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            self.file.close()
            from .errors import MeshError
            raise MeshError("ALREADY_RUNNING",str(path))
    def close(self):
        if not self.file.closed:self.file.close()


def local_socket(data:Path,service="swarm"):
    import hashlib
    path=Path(data)/(service+".sock")
    if len(os.fsencode(path))<100:return path
    uid=os.getuid() if hasattr(os,"getuid") else 0
    root=private_dir(Path(tempfile.gettempdir())/f"btx-ipc-{uid}")
    name=hashlib.sha384(str(Path(data).resolve()).encode()).hexdigest()[:24]
    return private_dir(root/name)/(service+".sock")
