"""Audit-control coverage analysis with narrower, semantics-aware heuristics."""
from __future__ import annotations
import ast,json,os,sys
from pathlib import Path
from common import add_fingerprint,read_ast
TARGET_MODULES=["importlib/_bootstrap_external.py","importlib/util.py","importlib/__init__.py","webbrowser.py","venv/__init__.py"]
OPEN_NAMES={"open","io.open","builtins.open","io.FileIO"}
SHELL_NAMES={"run","call","Popen","check_call","check_output","system","popen","execv","execve"}

def call_name(c):
    if isinstance(c.func,ast.Name):return c.func.id
    if isinstance(c.func,ast.Attribute):
        if isinstance(c.func.value,ast.Name):return f"{c.func.value.id}.{c.func.attr}"
        return c.func.attr
    return ""

def source_has_code_context(node):
    text=ast.unparse(node).lower()
    return any(x in text for x in (".pyc","bytecode","sourceless","get_code","get_data","loader"))

def scan_module(path):
    tree,src,error=read_ast(path)
    if error:
        return [{"domain":"AUD","module":Path(path).name,"function":"<parse error>","lineno":0,"issue":"Scanner could not parse source","sub_invariant":"N/A","confidence":"ANALYSIS-ERROR","evidence":error,"corpus_ref":None,"invariant":"Invariant 4: Audit Hook Coverage"}]
    out=[]
    for fn in [n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]:
        calls=[(call_name(c),c.lineno,c) for c in ast.walk(fn) if isinstance(c,ast.Call)]
        for name,ln,c in calls:
            if name in OPEN_NAMES and source_has_code_context(c):
                out.append(add_fingerprint({"domain":"AUD","module":Path(path).name,"function":fn.name,"lineno":ln,
                    "issue":"Potential code-loading path bypasses io.open_code() policy","sub_invariant":"4a","confidence":"SECURITY-CANDIDATE",
                    "evidence":f"{name}() appears in a loader/bytecode context at line {ln}. The generic 'open' audit event is not treated as equivalent to the code-opening policy; verify whether this path must call io.open_code().",
                    "corpus_ref":"AUD-001 (CVE-2026-2297)","invariant":"Invariant 4: Audit Hook Coverage"}))
        shell=[(n,l,c) for n,l,c in calls if n.split(".")[-1] in SHELL_NAMES]
        subst=[l for n,l,c in calls if n in {"format","replace"} or n.endswith("%")]
        checks=[l for n,l,c in calls if any(x in n.lower() for x in ("check","valid","sanitize","validate"))]
        if shell and subst and checks and min(checks)<min(subst)<min(l for _,l,_ in shell):
            out.append(add_fingerprint({"domain":"AUD","module":Path(path).name,"function":fn.name,"lineno":fn.lineno,
                "issue":"Validation lexically precedes command substitution before shell invocation","sub_invariant":"4b","confidence":"SECURITY-CANDIDATE",
                "evidence":f"Validation ({min(checks)}) precedes substitution ({min(subst)}) which precedes shell invocation ({min(l for _,l,_ in shell)}). This is only a candidate until the same value is traced through the expressions.",
                "corpus_ref":"AUD-002, AUD-003","invariant":"Invariant 4: Audit Hook Coverage"}))
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
