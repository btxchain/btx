// Copyright (c) 2026 The BTX developers. MIT license.
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <swapnet/embed.h>
#include <swapnet/frozen_sources.h>
#include <stdexcept>
#include <utility>
namespace swapnet {
namespace {
struct PyRef {
    PyObject* p{}; explicit PyRef(PyObject* v=nullptr):p(v){} ~PyRef(){Py_XDECREF(p);}
    PyRef(const PyRef&)=delete;PyRef& operator=(const PyRef&)=delete;
};
std::runtime_error PythonError(const char* operation) {
    // Record only the exception class and SwapError code. A traceback or
    // message can contain a preimage or a signed claim.
    std::string extra;
    if (PyErr_Occurred()) {
        PyObject *typ=nullptr,*val=nullptr,*tb=nullptr;
        PyErr_Fetch(&typ,&val,&tb);
        if (typ) {
            PyRef name(PyObject_GetAttrString(typ,"__name__"));
            if (name.p) {
                const char* n=PyUnicode_AsUTF8(name.p);
                if (n&&std::char_traits<char>::length(n)<=64) extra=std::string(" (")+n+")";
            }
        }
        if (val) {
            PyRef code(PyObject_GetAttrString(val,"code"));
            if (code.p) {
                const char* c=PyUnicode_AsUTF8(code.p);
                if (c&&std::char_traits<char>::length(c)<=40) extra+=' ', extra+=c;
            }
        }
        Py_XDECREF(typ);Py_XDECREF(val);Py_XDECREF(tb);
    }
    PyErr_Clear();
    return std::runtime_error(std::string("SwapNet engine error: ")+operation+extra);
}
PyObject* CoreCallback(PyObject* capsule,PyObject* args) {
    const char *wallet,*method,*params;
    if(!PyArg_ParseTuple(args,"sss",&wallet,&method,&params))return nullptr;
    auto* cb=static_cast<Callbacks*>(PyCapsule_GetPointer(capsule,"swapnet.callbacks"));
    if(!cb)return nullptr;
    try { auto result=cb->core(wallet,method,params);return PyUnicode_FromStringAndSize(result.data(),result.size()); }
    catch(...) {PyErr_SetString(PyExc_RuntimeError,"Native operation rejected");return nullptr;}
}
PyObject* SendCallback(PyObject* capsule,PyObject* args) {
    long long peer;const char *command,*payload;
    if(!PyArg_ParseTuple(args,"Lss",&peer,&command,&payload))return nullptr;
    auto* cb=static_cast<Callbacks*>(PyCapsule_GetPointer(capsule,"swapnet.callbacks"));if(!cb)return nullptr;
    try { return PyBool_FromLong(cb->send(peer,command,payload)); }
    catch(...) {PyErr_SetString(PyExc_RuntimeError,"Transport rejected");return nullptr;}
}
PyMethodDef CORE_METHOD={"core_call",CoreCallback,METH_VARARGS,"Internal native wallet bridge"};
PyMethodDef SEND_METHOD={"send",SendCallback,METH_VARARGS,"Bounded native transport enqueue"};
}
struct Engine::Impl {
    Callbacks callbacks;PyObject* host{};bool initialized{false};
    explicit Impl(Callbacks cb):callbacks(std::move(cb)){}
    ~Impl(){
        if(initialized){
            if(host){PyRef result(PyObject_CallMethod(host,"close",nullptr));PyErr_Clear();Py_DECREF(host);}
            Py_FinalizeEx();
        }
    }
};
Engine::Engine(const std::string& config,Callbacks callbacks):m(std::make_unique<Impl>(std::move(callbacks))) {
    if(Py_IsInitialized())throw std::runtime_error("SwapNet requires exclusive embedded Python ownership");
    // Isolated config leaves the C locale in place, so a non-ASCII datadir
    // (the functional runner uses one) raises UnicodeEncodeError. UTF-8 mode
    // is selected before initialization and does not read PYTHON* from the environment.
    PyPreConfig pre;PyPreConfig_InitIsolatedConfig(&pre);pre.utf8_mode=1;
    PyStatus prestatus=Py_PreInitialize(&pre);
    if(PyStatus_Exception(prestatus))throw std::runtime_error("SwapNet Python initialization failed");
    PyConfig cfg;PyConfig_InitIsolatedConfig(&cfg);
    cfg.install_signal_handlers=0;cfg.use_environment=0;cfg.user_site_directory=0;
    cfg.write_bytecode=0;cfg.safe_path=1;
    PyStatus status=Py_InitializeFromConfig(&cfg);PyConfig_Clear(&cfg);
    if(PyStatus_Exception(status))throw std::runtime_error("SwapNet Python initialization failed");
    m->initialized=true;
    if(PyRun_SimpleString(FROZEN_BOOTSTRAP)!=0)throw PythonError("frozen package load");
    PyRef module(PyImport_ImportModule("swapnet.embedded"));if(!module.p)throw PythonError("import");
    PyRef factory(PyObject_GetAttrString(module.p,"Host"));if(!factory.p)throw PythonError("Host lookup");
    PyRef capsule(PyCapsule_New(&m->callbacks,"swapnet.callbacks",nullptr));
    PyRef core(PyCFunction_New(&CORE_METHOD,capsule.p)),send(PyCFunction_New(&SEND_METHOD,capsule.p));
    PyRef config_obj(PyUnicode_FromStringAndSize(config.data(),config.size()));
    m->host=PyObject_CallFunctionObjArgs(factory.p,config_obj.p,core.p,send.p,nullptr);
    if(!m->host)throw PythonError("Host initialization");
}
Engine::~Engine()=default;
std::string Engine::Rpc(const std::string& principal,bool owner,const std::string& wallet,const std::string& method,const std::string& params) {
    PyRef result(PyObject_CallMethod(m->host,"rpc","sOsss",principal.c_str(),owner?Py_True:Py_False,wallet.c_str(),method.c_str(),params.c_str()));
    if(!result.p)throw PythonError("RPC");
    Py_ssize_t size{};const char* data=PyUnicode_AsUTF8AndSize(result.p,&size);
    if(!data||size>4*1024*1024)throw PythonError("RPC result");
    return std::string(data,size);
}
void Engine::Peer(std::int64_t id,bool connected){PyRef r(PyObject_CallMethod(m->host,"on_peer","LO",static_cast<long long>(id),connected?Py_True:Py_False));if(!r.p)throw PythonError("peer lifecycle");}
void Engine::Message(std::int64_t id,const std::string& command,const std::string& payload){PyRef r(PyObject_CallMethod(m->host,"on_message","Lss",static_cast<long long>(id),command.c_str(),payload.c_str()));if(!r.p)throw PythonError("peer message");}
void Engine::Tick(){PyRef r(PyObject_CallMethod(m->host,"tick",nullptr));if(!r.p)throw PythonError("tick");}
}
