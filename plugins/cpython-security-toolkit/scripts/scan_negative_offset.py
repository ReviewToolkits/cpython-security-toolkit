"""Detect attacker-controlled negative archive counters/offsets used unsafely.

Focuses on the actual historical failure mode: a decoded metadata integer is
used as a truthy ``while`` counter and is decremented, so a negative value never
reaches zero.  Benign ``for range(negative)`` is not reported as a security bug.
"""
from __future__ import annotations
import ast,json,os,sys
from pathlib import Path
from common import add_fingerprint,read_ast
TARGET_MODULES=["tarfile.py","zipfile/__init__.py","zipfile.py","plistlib.py","lzma.py"]
DECODE={"nti","unpack","unpack_from","frombytes","from_bytes","read_int"}
META={"offset","offset_data","blocks","size","compress_size","file_size","header_offset","count","length","dict_size","data_size","pos","block","entry_size"}

def names_in(node):
    return {n.id for n in ast.walk(node) if isinstance(n,ast.Name)}

def scan_module(path):
    tree,src,error=read_ast(path)
    if error:
        return [{"domain":"RES","module":Path(path).name,"function":"<parse error>","lineno":0,"issue":"Scanner could not parse source","sub_invariant":"N/A","confidence":"ANALYSIS-ERROR","evidence":error,"corpus_ref":None,"invariant":"Invariant 3: Resource Amplification Bound"}]
    out=[]
    for fn in [n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]:
        tainted=set()
        for a in ast.walk(fn):
            if isinstance(a,ast.Assign):
                value=a.value
                decoded=False
                if isinstance(value,ast.Call):
                    nm=value.func.attr if isinstance(value.func,ast.Attribute) else value.func.id if isinstance(value.func,ast.Name) else ""
                    decoded=nm in DECODE
                elif isinstance(value,ast.Attribute): decoded=value.attr in META
                if decoded:
                    for t in a.targets:
                        if isinstance(t,ast.Name):tainted.add(t.id)
        for w in [n for n in ast.walk(fn) if isinstance(n,ast.While)]:
            # Historical dangerous form: while count: ... count -= 1
            cond=names_in(w.test)&tainted
            if not cond:continue
            mutated=set()
            for n in ast.walk(w):
                if isinstance(n,ast.AugAssign) and isinstance(n.target,ast.Name) and n.target.id in cond:
                    if isinstance(n.op,(ast.Sub,ast.Add)):mutated.add(n.target.id)
                if isinstance(n,ast.Assign):
                    for t in n.targets:
                        if isinstance(t,ast.Name) and t.id in cond: mutated.add(t.id)
            for var in sorted(cond&mutated):
                # A guard anywhere in the while condition is evidence, not proof;
                # only a real explicit non-negative check suppresses the candidate.
                test=ast.unparse(w.test)
                if f"{var} >= 0" in test or f"{var} > 0" in test or f"{var} < 0" in test or f"{var} <= 0" in test:
                    continue
                out.append(add_fingerprint({"domain":"RES","module":Path(path).name,"function":fn.name,"lineno":w.lineno,
                    "issue":"Decoded archive counter controls a loop without a non-negative invariant","sub_invariant":"3c","confidence":"SECURITY-CANDIDATE",
                    "evidence":f"'{var}' is derived from archive metadata and controls a while-loop that mutates the same value, but the loop condition does not establish var >= 0. This matches the negative-counter infinite-loop class; confirm the exact mutation semantics.",
                    "corpus_ref":"RES-001 (CVE-2025-8194)","invariant":"Invariant 3: Resource Amplification Bound"}))
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
