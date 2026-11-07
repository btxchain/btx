"""Training-cohort state transitions and real compatible model aggregation.

The control journal names full update artifacts; it never carries gradients.
This is synchronous-at-round-boundary local SGD with optional outer momentum,
not a reproduction of the Decoupled DiLoCo algorithm or a WAN benchmark.
"""
import io
from .codec import fields,fixed_id,integer,digest,byte_id,encode,decode
from .errors import require

class CohortOps:
    def op_cohort_create(self,c,actor,b,now,term):
        fields(b,{'family','base_checkpoint','recipe','islands','min_islands','max_tokens','clip_micros','nonce'})
        family=self.get(c,'family',b['family']);self.member(c,family['realm'],actor,{'trainer','admin'})
        fixed_id(b['base_checkpoint']);fixed_id(b['recipe']);integer(b['min_islands'],2,128);integer(b['max_tokens'],1,10**12);integer(b['clip_micros'],1,10**12)
        require(isinstance(b['islands'],list) and b['min_islands']<=len(b['islands'])<=128 and len(set(b['islands']))==len(b['islands']),'COHORT_ISLANDS')
        for peer in b['islands']:self.member(c,family['realm'],peer,{'trainer'})
        id=digest('BTX/TrainingCohort/1',{'owner':actor,**b});require(self.get(c,'cohort',id,False) is None,'EXISTS')
        r={**b,'id':id,'realm':family['realm'],'owner':actor,'round':0,'state':'OPEN','optimizer_state':None,'last_updates':[]}
        self.put(c,'cohort',id,r);return r
    def op_cohort_submit(self,c,actor,b,now,term):
        fields(b,{'cohort','round','job','artifact','tokens','island_generation'})
        cohort=self.get(c,'cohort',b['cohort']);self.member(c,cohort['realm'],actor,{'trainer'})
        require(actor in cohort['islands'] and b['round']==cohort['round'] and cohort['state']=='OPEN','COHORT_ROUND')
        job=self.get(c,'job',b['job'])
        require(job['realm']==cohort['realm'] and job['executor']=='torch.train' and job['state']=='COMPLETE' and job['assigned']==actor,'COHORT_WORK')
        require(job['checkpoint']==cohort['base_checkpoint'] and job['recipe']==cohort['recipe'] and job['result_id']==b['artifact'],'COHORT_UPDATE_BINDING')
        integer(b['tokens'],1,cohort['max_tokens']);require(job['evidence'].get('tokens_seen')==b['tokens'],'COHORT_TOKEN_COUNT')
        require(job['generation']==b['island_generation'],'COHORT_GENERATION')
        key=digest('BTX/CohortUpdate/1',{'cohort':b['cohort'],'round':b['round'],'peer':actor})
        old=self.get(c,'cohort_update',key,False);r={**b,'id':key,'realm':cohort['realm'],'parent':cohort['id'],'peer':actor}
        require(old is None or old==r,'DUPLICATE_ISLAND_UPDATE');self.put(c,'cohort_update',key,r);return r
    def op_cohort_advance(self,c,actor,b,now,term):
        fields(b,{'cohort','round','updates','checkpoint','optimizer_state','aggregation_receipt'})
        cohort=self.get(c,'cohort',b['cohort']);self.member(c,cohort['realm'],actor,{'trainer','admin'})
        require(actor==cohort['owner'] and b['round']==cohort['round'],'COHORT_OWNER_OR_ROUND')
        require(isinstance(b['updates'],list) and cohort['min_islands']<=len(b['updates'])<=len(cohort['islands']) and len(set(b['updates']))==len(b['updates']),'ISLAND_QUORUM')
        peers=set()
        for id in b['updates']:
            update=self.get(c,'cohort_update',id)
            require(update['cohort']==cohort['id'] and update['round']==cohort['round'] and update['peer'] not in peers,'UPDATE_ROUND')
            self.member(c,cohort['realm'],update['peer'],{'trainer'});peers.add(update['peer'])
        for k in ('checkpoint','optimizer_state','aggregation_receipt'):fixed_id(b[k])
        record={**b,'realm':cohort['realm'],'parent':cohort['id'],'assurance':'AGGREGATOR_SIGNED_REQUIRES_INDEPENDENT_REPLAY'}
        self.put(c,'cohort_round',cohort['id']+':'+str(cohort['round']),record)
        cohort.update(base_checkpoint=b['checkpoint'],optimizer_state=b['optimizer_state'],round=cohort['round']+1,last_updates=sorted(b['updates']))
        self.put(c,'cohort',cohort['id'],cohort);return cohort


async def aggregate_round(client,cohort,updates,*,outer_lr_milli=1000,outer_momentum_milli=0):
    """Execute on an authorized coordinator with Worker-compatible transport/CAS.

    Result quality remains separate. A second aggregator can replay the ordered
    exact inputs and compare the checkpoint, optimizer and receipt commitments.
    """
    from .runtime import Decoder
    from .training import Cohort
    from . import tensors
    await client.fetch(cohort['base_checkpoint'])
    raw=client.store.read_bytes(client.realm,cohort['base_checkpoint'],max_bytes=1024**3)
    model=Decoder.from_checkpoint(raw)
    aggregator=Cohort(model.state_dict(),cohort['base_checkpoint'],cohort['recipe'],round_index=cohort['round'],min_islands=cohort['min_islands'],max_tokens=cohort['max_tokens'],clip_micros=cohort['clip_micros'])
    if cohort['optimizer_state']:
        await client.fetch(cohort['optimizer_state'])
        state=tensors.loads(client.store.read_bytes(client.realm,cohort['optimizer_state']))
        require(set(state)==set(aggregator.outer_velocity),'OUTER_OPTIMIZER_KEYS')
        for name,t in state.items():require(t.shape==aggregator.base[name].shape and t.dtype==aggregator.base[name].dtype,'OUTER_OPTIMIZER_SHAPE')
        aggregator.outer_velocity=state
    accepted=[]
    for update in sorted(updates,key=lambda u:u['peer']):
        require(update['cohort']==cohort['id'] and update['round']==cohort['round'],'UPDATE_ROUND')
        await client.fetch(update['artifact']);raw=client.store.read_bytes(client.realm,update['artifact'],max_bytes=1024**3)
        local=Decoder.from_checkpoint(raw)
        weights=tensors.dumps(local.state_dict())
        manifest={'base_checkpoint':cohort['base_checkpoint'],'recipe_id':cohort['recipe'],'round':cohort['round'],'tokens':update['tokens'],'artifact':byte_id(weights),'island_generation':update['island_generation']}
        aggregator.update(update['peer'],manifest,weights);accepted.append(update['id'])
    weights,receipt=aggregator.aggregate(outer_lr_milli=outer_lr_milli,outer_momentum_milli=outer_momentum_milli)
    model.load_state_dict(weights,strict=True)
    artifacts=[]
    for raw in (model.checkpoint(),tensors.dumps(aggregator.outer_velocity),encode(receipt)):
        id=client.store.put_bytes(client.realm,raw)['artifact'];await client.upload(id);artifacts.append(id)
    return await client.command('cohort.advance',{'cohort':cohort['id'],'round':cohort['round'],'updates':accepted,'checkpoint':artifacts[0],'optimizer_state':artifacts[1],'aggregation_receipt':artifacts[2]},id='advance:'+cohort['id'][:64]+':'+str(cohort['round']))
