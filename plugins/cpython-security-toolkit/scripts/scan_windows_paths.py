"""Flag archive extraction code that appears not to model Windows absolute paths.

This is a review aid, not a proof. Windows drive/UNC behavior must be tested on
Windows because POSIX path libraries cannot faithfully establish the invariant.
"""
from __future__ import annotations
import ast,json,os,sys
from pathlib import Path
from common import add_fingerprint,read_ast
TARGET_MODULES=["zipfile/__init__.py","tarfile.py","shutil.py"]
WINDOWS_TERMS=("ntpath","splitdrive","UNC","drive","isabs","altsep")
EXTRACT_HINTS=("extract","unpack","member")
def scan_module(path):
 tree,src,error=read_ast(path)
 if error:return [{"domain":"ARC","module":Path(path).name,"function":"<parse error>","lineno":0,"issue":"Scanner could not parse source","sub_invariant":"N/A","confidence":"ANALYSIS-ERROR","evidence":error,"corpus_ref":None,"invariant":"Invariant 1: Extraction Boundary"}]
 out=[]
 for fn in [n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]:
  if not any(h in fn.name.lower() for h in EXTRACT_HINTS):continue
  text=ast.unparse(fn).lower()
  if not any(t.lower() in text for t in WINDOWS_TERMS):
   out.append(add_fingerprint({"domain":"ARC","module":Path(path).name,"function":fn.name,"lineno":fn.lineno,"issue":"Extraction path has no visible Windows drive/UNC normalization handling","sub_invariant":"1c","confidence":"HARDENING","evidence":"No Windows-specific path normalization primitive was found in this extraction function. Run the Windows corpus tests before treating this as a security candidate.","corpus_ref":"ARC Windows path corpus","invariant":"Invariant 1: Extraction Boundary"}))
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
