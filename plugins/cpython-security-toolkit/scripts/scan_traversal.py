"""Conservative archive extraction boundary analysis.

The old engine treated any ``open()`` inside an extraction-looking function as a
vulnerability and ignored helper functions.  This version builds a small
intra-module call summary: boundary checks in helpers called by the extraction
function count as coverage, while unresolved helpers remain candidates rather
than SECURITY verdicts.
"""
from __future__ import annotations
import ast, json, os, sys
from pathlib import Path
from common import add_fingerprint, read_ast

TARGET_MODULES=["tarfile.py","zipfile/__init__.py","zipfile.py","shutil.py"]
WRITE_NAMES={"open","fdopen","copyfileobj","copy2","copyfile","write","makedirs","mkdir"}
RESOLVE_NAMES={"realpath","resolve","abspath","normpath"}
BOUNDARY_NAMES={"is_relative_to","commonpath","commonprefix"}
EXTRACT_HINTS=("extract","unpack","open_member","_open")


def calls(node):
    out=[]
    for n in ast.walk(node):
        if isinstance(n,ast.Call):
            if isinstance(n.func,ast.Name): out.append(n.func.id)
            elif isinstance(n.func,ast.Attribute): out.append(n.func.attr)
    return out


def scan_module(path):
    tree, source, error=read_ast(path)
    if error:
        return [{"domain":"ARC","module":Path(path).name,"function":"<parse error>","lineno":0,
                 "issue":"Scanner could not parse source","sub_invariant":"N/A","confidence":"ANALYSIS-ERROR",
                 "evidence":error,"corpus_ref":None,"invariant":"Invariant 1: Extraction Boundary"}]
    funcs={n.name:n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
    summaries={}
    for name,node in funcs.items():
        c=set(calls(node)); summaries[name]={
            "write":bool(c & WRITE_NAMES), "resolve":bool(c & RESOLVE_NAMES), "boundary":bool(c & BOUNDARY_NAMES),
            "calls":c,
        }
    out=[]
    for name,node in funcs.items():
        if not any(h in name.lower() for h in EXTRACT_HINTS): continue
        c=set(calls(node)); direct=summaries[name]
        called=[summaries[x] for x in c if x in summaries]
        has_write=direct["write"] or any(x["write"] for x in called)
        has_boundary=direct["boundary"] or any(x["boundary"] for x in called)
        has_resolve=direct["resolve"] or any(x["resolve"] for x in called)
        if has_write and not has_boundary:
            out.append(add_fingerprint({
                "domain":"ARC","module":Path(path).name,"function":name,"lineno":node.lineno,
                "issue":"Extraction write path has no statically resolved destination-boundary check",
                "sub_invariant":"1a","confidence":"SECURITY-CANDIDATE",
                "evidence":f"{name} performs or delegates a filesystem write, but no boundary helper was resolved in-module. Calls to external helpers are intentionally unresolved.",
                "corpus_ref":"ARC-001 through ARC-007","invariant":"Invariant 1: Extraction Boundary"}))
        if has_boundary and has_resolve:
            # Only report if a single lexical path clearly performs boundary before resolution.
            positions=[]
            for n in ast.walk(node):
                if isinstance(n,ast.Call):
                    nm=n.func.attr if isinstance(n.func,ast.Attribute) else (n.func.id if isinstance(n.func,ast.Name) else "")
                    if nm in BOUNDARY_NAMES or nm in RESOLVE_NAMES: positions.append((n.lineno,nm))
            b=[l for l,nm in positions if nm in BOUNDARY_NAMES]; r=[l for l,nm in positions if nm in RESOLVE_NAMES]
            if b and r and min(b)<min(r):
                out.append(add_fingerprint({
                    "domain":"ARC","module":Path(path).name,"function":name,"lineno":node.lineno,
                    "issue":"Destination boundary check lexically precedes path resolution",
                    "sub_invariant":"1b","confidence":"SECURITY-CANDIDATE",
                    "evidence":f"Boundary call at line {min(b)} precedes resolution at line {min(r)} in the same function. Runtime path semantics and helper ordering still require reproducer confirmation.",
                    "corpus_ref":"ARC-003, ARC-005","invariant":"Invariant 1: Extraction Boundary"}))
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
