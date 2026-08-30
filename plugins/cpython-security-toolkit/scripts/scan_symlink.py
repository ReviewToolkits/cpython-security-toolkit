"""Detect archive link handling that lacks a resolvable destination check."""
from __future__ import annotations
import ast,json,os,sys
from pathlib import Path
from common import add_fingerprint,read_ast
TARGET_MODULES=["tarfile.py","zipfile/__init__.py","zipfile.py","shutil.py"]
LINK_NAMES={"SYMTYPE","LNKTYPE","symlink","link","readlink","resolve_symlinks","follow_symlinks"}
BOUNDARY_NAMES={"is_relative_to","commonpath","commonprefix"}
RESOLVE_NAMES={"realpath","resolve","abspath"}

def scan_module(path):
    tree,src,error=read_ast(path)
    if error:
        return [{"domain":"ARC","module":Path(path).name,"function":"<parse error>","lineno":0,"issue":"Scanner could not parse source","sub_invariant":"N/A","confidence":"ANALYSIS-ERROR","evidence":error,"corpus_ref":None,"invariant":"Invariant 1: Extraction Boundary"}]
    out=[]
    for node in ast.walk(tree):
        if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)): continue
        if not any(x in node.name.lower() for x in ("extract","unpack","member")): continue
        names=[]
        for c in ast.walk(node):
            if isinstance(c,ast.Call): names.append(c.func.attr if isinstance(c.func,ast.Attribute) else c.func.id if isinstance(c.func,ast.Name) else "")
            elif isinstance(c,ast.Attribute): names.append(c.attr)
        links=set(names)&LINK_NAMES
        if links and not (set(names)&BOUNDARY_NAMES):
            out.append(add_fingerprint({"domain":"ARC","module":Path(path).name,"function":node.name,"lineno":node.lineno,
                "issue":"Archive link handling has no visible destination-boundary validation","sub_invariant":"1b","confidence":"SECURITY-CANDIDATE",
                "evidence":f"Link-related operations {sorted(links)} occur in {node.name}, but no recognized boundary check is visible in that function. Helper/caller checks require manual tracing.",
                "corpus_ref":"ARC-001 through ARC-005","invariant":"Invariant 1: Extraction Boundary"}))
    return out

def scan(lib_dir):
    out=[]
    for rel in TARGET_MODULES:
        p=os.path.join(lib_dir,rel.replace("/",os.sep))
        if os.path.exists(p): out.extend(scan_module(p))
    return out
if __name__=="__main__":
    if len(sys.argv)<2: raise SystemExit(f"Usage: {sys.argv[0]} <cpython-lib-dir>")
    r=scan(sys.argv[1]); print(json.dumps(r,indent=2)); print(f"Total: {len(r)}",file=sys.stderr)
