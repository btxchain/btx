"""Run from package root: python -m reference.demo (fully offline)."""
from pathlib import Path
import json
from .simulator import Simulation
r=Path(__file__).resolve().parents[1]
body=json.loads((r/'examples/FinanceIntent.unsigned.json').read_text())['body']
policy=json.loads((r/'examples/HostedAccountPolicy.json').read_text())
s=Simulation(10000,policy);i=s.create(body);s.authorize(i,i.digest,1790000000100);s.reserve(i,1790000000100)
s.simulate_sign(i);before=s.simulate_dispatch(i,response_lost=True)
held=s.summary();retry=s.simulate_dispatch(i);s.simulate_confirm(i,20)
print(json.dumps({'warning':'SIMULATION ONLY: no real signing, network, funds or runtime',
 'after_lost_response':held,'retry_reuses_same_simulated_reference':before==retry,
 'after_simulated_confirmation':s.summary()},indent=2))
