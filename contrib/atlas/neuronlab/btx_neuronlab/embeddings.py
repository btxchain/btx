"""Content-addressed, bounded embedding datasets and streaming scientific projections.

Raw high-dimensional vectors remain available for exact-neighbour queries; a 2D
picture is never treated as a semantic or causal metric. No pickle/model loading.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.metadata
import math
import os
from pathlib import Path
import shutil
import tempfile
import numpy as np
from .codec import require, integer, keys, canonical, loads, identity, sha384, read_file, atomic_write, digest_text, LabError

MAX_ROWS=1_000_000
MAX_DIMS=8192
MAX_INPUT=512*1024*1024
CHUNK_ROWS=4096
MAX_PAGE_ROWS=32768
GROUPS=('neuron','prompt','dose','kind')


def hash_file(path):
    require(not path.is_symlink() and path.is_file(),'FILE','Regular non-symlink input required')
    h=hashlib.sha384()
    with path.open('rb') as f:
        while b:=f.read(4*1024*1024):h.update(b)
    return h.hexdigest()


def slices(n,step=CHUNK_ROWS):
    start=0
    while start<n:
        end=min(n,start+step)
        if n-end==1:end=n
        yield start,end
        start=end


def finite_matrix(path):
    require(path.suffix.lower()=='.npy' and not path.is_symlink(),'MATRIX','Select a numeric .npy matrix; pickle and NPZ archives are not accepted')
    require(path.stat().st_size<=MAX_INPUT+65536,'MATRIX_BUDGET','Input matrix exceeds byte budget')
    try:a=np.load(path,mmap_mode='r',allow_pickle=False,max_header_size=16384)
    except (ValueError,OSError) as e:raise LabError('MATRIX','Invalid non-pickle NumPy matrix') from e
    require(a.ndim==2 and 2<=a.shape[0]<=MAX_ROWS and 2<=a.shape[1]<=MAX_DIMS,'MATRIX_SHAPE','Matrix requires 2..1M rows and 2..8192 features')
    require(a.dtype in (np.dtype('float32'),np.dtype('float64')) and a.nbytes<=MAX_INPUT,'MATRIX_DTYPE','Only bounded float32/float64 data is accepted')
    require(a.flags.c_contiguous,'MATRIX_ORDER','Input must be C contiguous')
    for lo,hi in slices(len(a)):
        require(np.isfinite(a[lo:hi]).all(),'NONFINITE','Embedding matrix contains NaN/infinity')
    return a


def _project(a,out,method,seed,progress=None):
    n,d=a.shape
    require(method in {'pca','umap','tsne'},'PROJECTION','Unknown projection method')
    integer(seed,0,2**31-1)
    if method=='pca':
        from sklearn.decomposition import IncrementalPCA
        reducer=IncrementalPCA(n_components=2,batch_size=512)
        for lo,hi in slices(n,512):
            reducer.partial_fit(np.asarray(a[lo:hi],dtype=np.float64))
            if progress:progress({'type':'embedding-progress','phase':'fit','rows':hi,'total':n})
        # Fix sign convention for this run; degenerate eigenspaces are still not
        # unique across platforms/BLAS versions and are labelled accordingly.
        for c in reducer.components_:
            if c[np.abs(c).argmax()]<0:c*=-1
        for lo,hi in slices(n):out[lo:hi]=reducer.transform(a[lo:hi]).astype('<f4')
        explained=np.nan_to_num(reducer.explained_variance_ratio_,nan=0,posinf=0,neginf=0)
        return {'method':'INCREMENTAL_PCA','fit_rows':n,'seed_recorded':seed,'seed_used':False,
                'sklearn':importlib.metadata.version('scikit-learn'),'explained_variance_ppm':[round(float(v)*1e6)for v in explained],
                'coordinates_bitwise_portable':False,'landmark_fit':False}
    if method=='umap':
        try:import umap
        except ImportError as e:raise LabError('UMAP_NOT_INSTALLED','Install and audit optional umap-learn; PCA is never silently substituted for UMAP')from e
        rng=np.random.default_rng(seed);size=min(n,8192)
        indices=np.sort(rng.choice(n,size=size,replace=False))
        train=np.asarray(a[indices],dtype=np.float32)
        reducer=umap.UMAP(n_components=2,n_neighbors=min(15,size-1),random_state=seed,transform_seed=seed,n_jobs=1)
        fitted=reducer.fit_transform(train)
        for lo,hi in slices(n):
            out[lo:hi]=reducer.transform(np.asarray(a[lo:hi],dtype=np.float32))
            if progress:progress({'type':'embedding-progress','phase':'transform','rows':hi,'total':n})
        out[indices]=fitted
        return {'method':'UMAP' if size==n else 'LANDMARK_UMAP_WITH_TRANSFORM','fit_rows':size,'seed':seed,
                'fit_indices_hash':sha384(indices.astype('<u4').tobytes()),'umap':importlib.metadata.version('umap-learn'),
                'coordinates_bitwise_portable':False,'landmark_fit':size<n}
    from sklearn.manifold import TSNE
    require(n<=20000 and n*d*4<=64*1024*1024,'TSNE_BUDGET','t-SNE is limited to 20k rows and 64MiB; select a declared subset')
    reducer=TSNE(n_components=2,perplexity=min(30,max(1,(n-1)/3)),random_state=seed,init='pca',learning_rate='auto')
    out[:]=reducer.fit_transform(np.asarray(a,dtype=np.float32))
    return {'method':'TSNE','fit_rows':n,'seed':seed,'sklearn':importlib.metadata.version('scikit-learn'),
            'coordinates_bitwise_portable':False,'landmark_fit':False}


class Embeddings:
    def __init__(self,root):
        self.root=Path(root)/'embeddings';self.root.mkdir(mode=0o700,exist_ok=True)
        require(not self.root.is_symlink(),'SYMLINK','Dataset root must not be a symlink')
    def build(self,path,*,title='Local embeddings',method='pca',seed=42,groups=None,provenance=None,progress=None):
        from .codec import text
        text(title,160)
        path=Path(path);a=finite_matrix(path);source_hash=hash_file(path);n,d=a.shape
        # Total storage budget independent of projection or GUI request count.
        existing=sum(p.stat().st_size for p in self.root.glob('*/*') if p.is_file())
        estimate=n*(d*a.dtype.itemsize+24)+1048576
        require(existing+estimate<=2*1024**3,'DISK_BUDGET','Embedding store exceeds its 2GiB local budget')
        group_data=np.zeros((n,4),dtype='<u4') if groups is None else np.asarray(groups)
        require(group_data.shape==(n,4) and group_data.dtype.kind in 'ui' and (group_data>=0).all() and (group_data<=2**32-1).all(),'GROUPS','Four nonnegative uint32 category columns required')
        group_data=np.asarray(group_data,dtype='<u4')
        temp=Path(tempfile.mkdtemp(prefix='.pending-',dir=self.root));os.chmod(temp,0o700)
        try:
            coords=np.memmap(temp/'coordinates.tmp',mode='w+',shape=(n,2),dtype='<f4')
            projection=_project(a,coords,method,seed,progress)
            require(np.isfinite(coords).all(),'NONFINITE','Projection produced invalid coordinates')
            chunks=[]
            # Each independently verifiable chunk has fixed framing/dimensions.
            for i,(lo,hi) in enumerate(slices(n)):
                vectors=np.asarray(a[lo:hi],dtype='<f4' if a.dtype.itemsize==4 else '<f8').tobytes()
                view=np.asarray(coords[lo:hi],dtype='<f4').tobytes()+group_data[lo:hi].tobytes()
                vp=f'{i:06d}.vectors';pp=f'{i:06d}.points'
                atomic_write(temp/vp,vectors);atomic_write(temp/pp,view)
                chunks.append({'start':lo,'count':hi-lo,'vectors':vp,'vector_sha384':sha384(vectors),
                               'points':pp,'point_sha384':sha384(view)})
                if progress:progress({'type':'embedding-progress','phase':'store','rows':hi,'total':n})
            bounds=[float(coords[:,i].min()) for i in (0,1)]+[float(coords[:,i].max())for i in (0,1)]
            require(all(abs(x)<1e12 for x in bounds),'PROJECTION_RANGE','Coordinates exceed declared visualization range')
            meta={'schema':'btx.neuronlab.embeddings/2','title':title,'rows':n,'dimensions':d,
                  'source_file_sha384':source_hash,'source_dtype':a.dtype.str,'stored_dtype':'<f4' if a.dtype.itemsize==4 else '<f8','projection':projection,
                  'bounds_millionths':[round(x*1e6)for x in bounds],'groups':list(GROUPS),'chunks':chunks,
                  'provenance':provenance or {'scope':'USER_IMPORTED_MATRIX','semantic_labels_verified':False},
                  'privacy':'PRIVATE_LOCAL_DATASET','raw_metric_preserved':True}
            require(hash_file(path)==source_hash,'INPUT_CHANGED','Input changed while projection was being built')
            dataset_id=identity('BTX/NeuronLab/EmbeddingDataset/2',meta)
            atomic_write(temp/'manifest.json',canonical(meta))
            del coords;(temp/'coordinates.tmp').unlink()
            destination=self.root/dataset_id
            if destination.exists():
                self.manifest(dataset_id);shutil.rmtree(temp)
            else:os.rename(temp,destination)
            return {'id':dataset_id,**self.summary(meta)}
        except BaseException:
            shutil.rmtree(temp,ignore_errors=True);raise
    def manifest(self,dataset_id):
        digest_text(dataset_id);directory=self.root/dataset_id
        require(not directory.is_symlink(),'SYMLINK','Dataset directory must be local')
        m=loads(read_file(directory/'manifest.json',1_048_576))
        require(identity('BTX/NeuronLab/EmbeddingDataset/2',m)==dataset_id,'DATASET_CHANGED','Dataset manifest changed')
        require(m['schema']=='btx.neuronlab.embeddings/2','DATASET_VERSION','Unknown dataset')
        return m
    @staticmethod
    def summary(m):return {k:m[k] for k in ['title','rows','dimensions','projection','bounds_millionths','groups','privacy','provenance','source_dtype','stored_dtype']}
    def list(self):
        items=[]
        for p in sorted(self.root.iterdir()):
            if p.name.startswith('.'):continue
            if len(items)>=100:break
            m=self.manifest(p.name);items.append({'id':p.name,**self.summary(m)})
        return {'items':items,'limit':100,'scope':'LOCAL_ONLY'}
    def _chunk(self,dataset_id,m,c,kind):
        count,dim=c['count'],m['dimensions'];name=c[kind]
        require('/'not in name and '\\'not in name and '..'not in name,'PATH','Unexpected chunk path')
        dtype=m.get('stored_dtype','<f4');require(dtype in {'<f4','<f8'},'DATASET_DTYPE','Unknown stored precision')
        size=count*dim*np.dtype(dtype).itemsize if kind=='vectors' else count*24
        raw=read_file(self.root/dataset_id/name,size)
        require(len(raw)==size and sha384(raw)==c['vector_sha384' if kind=='vectors'else'point_sha384'],'CHUNK_INTEGRITY','Embedding chunk changed')
        if kind=='vectors':return np.frombuffer(raw,dtype=dtype).reshape(count,dim)
        xy=np.frombuffer(raw[:count*8],dtype='<f4').reshape(count,2)
        cats=np.frombuffer(raw[count*8:],dtype='<u4').reshape(count,4)
        return xy,cats
    def page(self,dataset_id,offset=0,limit=4096,stride=1):
        m=self.manifest(dataset_id);integer(offset,0,m['rows']);integer(limit,1,MAX_PAGE_ROWS);integer(stride,1,MAX_ROWS)
        indices=np.arange(offset,min(m['rows'],offset+limit*stride),stride,dtype='<u4')
        xy=np.empty((len(indices),2),dtype='<f4');cats=np.empty((len(indices),4),dtype='<u4')
        for c in m['chunks']:
            mask=(indices>=c['start'])&(indices<c['start']+c['count'])
            if not mask.any():continue
            a,b=self._chunk(dataset_id,m,c,'points');local=indices[mask]-c['start'];xy[mask]=a[local];cats[mask]=b[local]
        next_offset=offset+len(indices)*stride
        return {'schema':'btx.neuronlab.embedding-page/2','dataset_id':dataset_id,'count':len(indices),
                'coordinates_f32_le':base64.b64encode(xy.tobytes()).decode(),
                'categories_u32_le':base64.b64encode(cats.tobytes()).decode(),
                'row_ids_u32_le':base64.b64encode(indices.tobytes()).decode(),
                'next_offset':next_offset if next_offset<m['rows']else None,'stride':stride,'sampled':stride>1,
                'total_rows':m['rows'],'complete':stride==1 and offset==0 and next_offset>=m['rows']}
    def neighbors(self,dataset_id,row,k=16,metric='cosine',progress=None):
        m=self.manifest(dataset_id);integer(row,0,m['rows']-1);integer(k,1,64)
        require(metric in {'cosine','euclidean'},'DISTANCE','Choose original-space cosine or Euclidean distance')
        c=next(c for c in m['chunks'] if c['start']<=row<c['start']+c['count'])
        q=self._chunk(dataset_id,m,c,'vectors')[row-c['start']].astype(np.float64)
        qnorm=np.linalg.norm(q)
        require(metric!='cosine' or qnorm>1e-12,'ZERO_VECTOR','Cosine distance undefined for a zero query vector')
        best=[];undefined=0
        for c in m['chunks']:
            a=self._chunk(dataset_id,m,c,'vectors').astype(np.float64)
            if metric=='euclidean':dist=np.linalg.norm(a-q,axis=1)
            else:
                norms=np.linalg.norm(a,axis=1);valid=norms>1e-12;undefined+=int((~valid).sum())
                dist=np.full(len(a),np.inf);dist[valid]=1-(a[valid]@q)/(norms[valid]*qnorm)
                dist[valid]=np.clip(dist[valid],0,2)
            if c['start']<=row<c['start']+c['count']:dist[row-c['start']]=np.inf
            count=min(k,len(a));idx=np.argpartition(dist,count-1)[:count]
            best += [(float(dist[i]),int(c['start']+i))for i in idx if np.isfinite(dist[i])]
            best=sorted(best)[:k]
            if progress:progress({'type':'embedding-progress','phase':'neighbors','rows':c['start']+c['count'],'total':m['rows']})
        return {'dataset_id':dataset_id,'query_row':row,'space':'ORIGINAL_HIGH_DIMENSIONAL_VECTORS','metric':metric,
                'neighbors':[{'row':i,'distance_millionths':round(v*1e6)}for v,i in best],
                'undefined_zero_vectors':undefined,'two_dimensional_distance_is_not_used':True}
