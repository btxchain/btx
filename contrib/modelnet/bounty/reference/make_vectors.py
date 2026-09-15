from pathlib import Path
import copy,json
from bounty_reference import digest,preimage
body={'envelope_version':1,'record_type':'BountyTerms','network_id':'00'*32,'signer_id':'11'*48,'public_key_hex':'22'*1312,'delegation_id':None,'payload':{'title':'日本語 coding model','target_atoms':'50000000000','tags':['coding','tool-use'],'tombstone':False}}
vec=[]
for name,changes in [('base',{}),('different_network',{'network_id':'01'*32}),('tombstone',{'payload':dict(body['payload'],tombstone=True)}),('description_change',{'payload':dict(body['payload'],description='For repository maintenance')})]:
 b=copy.deepcopy(body);b.update(changes);vec.append({'name':name,'body':b,'preimage_hex':preimage(b).hex(),'sha384':digest(b)})
Path(__file__).with_name('golden-vectors.json').write_text(json.dumps({'notice':'Synthetic preimage fixtures only. Keys are placeholder bytes, no signatures are generated or verified, and these compact payloads are not complete BountyTerms schema instances.','vectors':vec},ensure_ascii=False,indent=2)+'\n')
