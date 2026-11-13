import os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pytest
from swapnet.assets import Asset
from swapnet.store import Store
from swapnet.policy import Mandate
from swapnet.quote import Quote
NET='a'*64
BTX=Asset('btx',NET).id
BTC=Asset('btc','b'*64).id
NOW=1800000000
@pytest.fixture
def store(tmp_path):
    os.chmod(tmp_path,0o700)
    s=Store(tmp_path/'state.sqlite')
    yield s
    s.close()
@pytest.fixture
def quote():
    return Quote(NET,'maker','c'*64,'d'*64,1,BTX,BTC,'10000','20000','100','200',NOW,NOW+90)
@pytest.fixture
def mandate():return Mandate('agent',BTX,'25000','11000','1000',NOW+1000,'e'*64)
