import base64
import copy
import importlib.util
import numpy as np
import pytest
from btx_neuronlab.codec import LabError
from btx_neuronlab.embeddings import Embeddings,finite_matrix

def source(tmp_path,n=64,d=8,dtype='float32'):
    path=tmp_path/'vectors.npy';a=np.random.default_rng(43).normal(size=(n,d)).astype(dtype);np.save(path,a);return path,a

def test_projection_pages_and_original_neighbors(tmp_path):
    path,a=source(tmp_path,70);store=Embeddings(tmp_path);m=store.build(path);r=store.page(m['id'],0,17)
    xy=np.frombuffer(base64.b64decode(r['coordinates_f32_le']),dtype='<f4').reshape(-1,2)
    assert xy.shape==(17,2) and r['next_offset']==17
    ids=[];offset=0
    while offset is not None:
        p=store.page(m['id'],offset,17);ids.extend(np.frombuffer(base64.b64decode(p['row_ids_u32_le']),dtype='<u4'));offset=p['next_offset']
    assert ids==list(range(70))
    near=store.neighbors(m['id'],0,k=7,metric='euclidean')
    expected=np.argsort(np.linalg.norm(a-a[0],axis=1))[1:8].tolist()
    assert [r['row']for r in near['neighbors']]==expected and near['two_dimensional_distance_is_not_used']
    assert store.list()['items'][0]['id']==m['id']

def test_float64_vectors_not_silently_quantized(tmp_path):
    path,a=source(tmp_path,dtype='float64');e=Embeddings(tmp_path);m=e.build(path);meta=e.manifest(m['id'])
    assert meta['stored_dtype']=='<f8'
    actual=e._chunk(m['id'],meta,meta['chunks'][0],'vectors');assert np.array_equal(actual,a)

def test_chunk_integrity_refusal(tmp_path):
    path,a=source(tmp_path);e=Embeddings(tmp_path);m=e.build(path);manifest=e.manifest(m['id'])
    p=e.root/m['id']/manifest['chunks'][0]['points'];data=bytearray(p.read_bytes());data[-1]^=1;p.write_bytes(data)
    with pytest.raises(LabError,match='changed'):e.page(m['id'])

def test_stride_and_deterministic_pca(tmp_path):
    path,_=source(tmp_path,65);e=Embeddings(tmp_path);a=e.build(path);b=e.build(path);assert a['id']==b['id']
    page=e.page(a['id'],0,5,3);assert page['sampled'] and page['next_offset']==15
    assert np.frombuffer(base64.b64decode(page['row_ids_u32_le']),dtype='<u4').tolist()==[0,3,6,9,12]

def test_chunk_boundary_and_partial_fit_last_singleton(tmp_path):
    path,_=source(tmp_path,4097,2);e=Embeddings(tmp_path);m=e.build(path)
    p=e.page(m['id'],4095,2);assert p['count']==2 and p['next_offset'] is None

@pytest.mark.parametrize('kind',['nan','object','int','fortran','shape','link'])
def test_invalid_matrix_refuses(tmp_path,kind):
    path,a=source(tmp_path)
    if kind=='nan':a[0,0]=np.nan
    elif kind=='object':a=a.astype(object)
    elif kind=='int':a=a.astype('int32')
    elif kind=='fortran':a=np.asfortranarray(a)
    elif kind=='shape':a=a[:1]
    elif kind=='link':
        other=tmp_path/'link.npy';other.symlink_to(path)
        with pytest.raises(LabError):finite_matrix(other)
        return
    np.save(path,a)
    with pytest.raises(LabError):finite_matrix(path)

def test_zero_cosine_and_unknown_projection(tmp_path):
    path,a=source(tmp_path);a[0]=0;np.save(path,a);e=Embeddings(tmp_path);m=e.build(path)
    with pytest.raises(LabError,match='zero'):e.neighbors(m['id'],0)
    with pytest.raises(LabError):e.build(path,method='not-a-method')

def test_optional_umap_is_never_substituted(tmp_path):
    if importlib.util.find_spec('umap') is not None:pytest.skip('Environment has real UMAP; test its integration separately')
    path,_=source(tmp_path);e=Embeddings(tmp_path)
    with pytest.raises(LabError)as exc:e.build(path,method='umap')
    assert exc.value.code=='UMAP_NOT_INSTALLED' and not list(e.root.glob('.pending-*'))

def test_actual_tsne(tmp_path):
    path,_=source(tmp_path,40,6);e=Embeddings(tmp_path);m=e.build(path,method='tsne',seed=7)
    assert m['projection']['method']=='TSNE';assert e.page(m['id'])['count']==40
