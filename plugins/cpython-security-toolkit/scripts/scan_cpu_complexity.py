"""Conservative attacker-input complexity heuristics.

A string method inside any loop is not automatically quadratic.  We require a
reasonable data-flow signal: the function receives a string-like argument and
the same value (or a value derived from it) participates in the loop. Regex
warnings are candidates unless the pattern is actually applied to a parameter.
"""
from __future__ import annotations
import ast,json,os,re,sys
from pathlib import Path
from common import add_fingerprint,read_ast
TARGET_MODULES=["http/cookies.py","email/_parseaddr.py","email/feedparser.py","email/headerregistry.py","http/client.py","urllib/parse.py"]
STRING_OPS={"find","index","count","replace","split","startswith","endswith","strip","lstrip","rstrip"}
DANGEROUS_REGEX=[r"\(\.\*\).*\+",r"\.\*.*\.\*",r"\(\w\+\)\+"]

def scan_module(path):
    tree,src,error=read_ast(path)
    if error:return [{"domain":"RES","module":Path(path).name,"function":"<parse error>","lineno":0,"issue":"Scanner could not parse source","sub_invariant":"N/A","confidence":"ANALYSIS-ERROR","evidence":error,"corpus_ref":None,"invariant":"Invariant 3: Resource Amplification Bound"}]
    out=[]
    for fn in [n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]:
        params={a.arg for a in fn.args.args}
        stringish={p for p in params if p.lower() in {"s","text","data","value","header","url","name","input","line","value"}}
        for loop in [n for n in ast.walk(fn) if isinstance(n,(ast.For,ast.While))]:
            for c in ast.walk(loop):
                if isinstance(c,ast.Call) and isinstance(c.func,ast.Attribute) and c.func.attr in STRING_OPS:
                    recv=c.func.value
                    if isinstance(recv,ast.Name) and recv.id in stringish:
                        out.append(add_fingerprint({"domain":"RES","module":Path(path).name,"function":fn.name,"lineno":c.lineno,
                            "issue":f"Potential super-linear string processing on attacker-derived parameter via {c.func.attr}()","sub_invariant":"3d","confidence":"HARDENING",
                            "evidence":f"Parameter '{recv.id}' participates in {c.func.attr}() inside a loop. Static analysis cannot establish iteration/input coupling, so this is hardening guidance rather than a security finding.","corpus_ref":"RES-007, RES-008","invariant":"Invariant 3: Resource Amplification Bound"}))
        for c in ast.walk(fn):
            if isinstance(c,ast.Call) and isinstance(c.func,ast.Attribute) and c.func.attr in {"match","search","findall","split"}:
                for arg in c.args:
                    if isinstance(arg,ast.Name) and arg.id in stringish:
                        # Inspect nearby regex literal only when available in the call.
                        pattern=None
                        if c.func.attr in {"match","search","findall","split"} and isinstance(c.func.value,ast.Name):
                            pattern=None
                        text=ast.unparse(c)
                        if any(re.search(p,text) for p in DANGEROUS_REGEX):
                            out.append(add_fingerprint({"domain":"RES","module":Path(path).name,"function":fn.name,"lineno":c.lineno,
                                "issue":"Potential catastrophic regex backtracking on attacker-derived input","sub_invariant":"3d","confidence":"SECURITY-CANDIDATE",
                                "evidence":f"Regex operation at line {c.lineno} consumes parameter '{arg.id}' and the expression contains a nested-quantifier pattern. Reproduce before escalation.","corpus_ref":"RES-003","invariant":"Invariant 3: Resource Amplification Bound"}))
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
