"""Security-sensitive value validation coverage analysis.

This engine is path-aware at the class level.  It recognizes delegation (for
example ``Morsel.__ior__ -> update``) and semantic validators such as
``_has_control_character`` so a safe implementation is not reported merely
because validation happens in a helper.
"""
from __future__ import annotations
import ast,json,os,sys
from pathlib import Path
from common import add_fingerprint,read_ast
TARGET_MODULES=["http/cookies.py","http/client.py","wsgiref/headers.py","urllib/request.py","urllib/parse.py"]
VALIDATORS={"_is_legal_key","_is_legal_value","_has_control_character","_is_illegal_header_value","_check_name","valid_header_name","valid_header_value","_quote","_unquote"}
MUTATORS={"__setitem__","update","__ior__","__setstate__","set","add","append"}
OUTPUTS={"output","js_output","__str__","__repr__","encode"}

def method_map(cls): return {n.name:n for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}

def direct_calls(node):
    out=set()
    for n in ast.walk(node):
        if isinstance(n,ast.Call):
            out.add(n.func.attr if isinstance(n.func,ast.Attribute) else n.func.id if isinstance(n.func,ast.Name) else "")
    return out

def closure_validated(name,methods,seen=None):
    seen=set() if seen is None else seen
    if name in seen or name not in methods:return False
    seen.add(name); calls=direct_calls(methods[name])
    if calls & VALIDATORS:return True
    return any(closure_validated(c,methods,seen) for c in calls if c in methods)

def scan_module(path):
    tree,src,error=read_ast(path)
    if error:
        return [{"domain":"PRO","module":Path(path).name,"class":"<parse error>","function":"<parse error>","lineno":0,"issue":"Scanner could not parse source","sub_invariant":"N/A","confidence":"ANALYSIS-ERROR","evidence":error,"corpus_ref":None,"invariant":"Invariant 2: Validation Coverage"}]
    out=[]
    for cls in [n for n in ast.walk(tree) if isinstance(n,ast.ClassDef)]:
        methods=method_map(cls); mut=[m for m in methods if m in MUTATORS]
        if not mut: continue
        covered=[m for m in mut if closure_validated(m,methods)]
        uncovered=[m for m in mut if m not in covered]
        if covered and uncovered:
            out.append(add_fingerprint({"domain":"PRO","module":Path(path).name,"class":cls.name,
                "function":",".join(uncovered),"lineno":cls.lineno,"covered_paths":covered,"uncovered_paths":uncovered,
                "issue":"Security-sensitive mutation paths have inconsistent validation coverage","sub_invariant":"2a",
                "confidence":"SECURITY-CANDIDATE","evidence":f"In class {cls.name}, validation reaches {covered} directly or through in-class delegation, but not {uncovered}. Verify that these methods accept the same security-sensitive value type.",
                "corpus_ref":"PRO-001, PRO-002","invariant":"Invariant 2: Validation Coverage"}))
    return out

def scan(lib_dir):
    out=[]
    for rel in TARGET_MODULES:
        p=os.path.join(lib_dir,rel.replace("/",os.sep))
        if os.path.exists(p):out.extend(scan_module(p))
    return out
if __name__=="__main__":
    if len(sys.argv)<2:raise SystemExit(f"Usage: {sys.argv[0]} <cpython-lib-dir>")
    r=scan(sys.argv[1]);print(json.dumps(r,indent=2));print(f"Total: {len(r)}",file=sys.stderr)
