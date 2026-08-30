"""Reproducible CPython checkout preflight for security scans."""
from __future__ import annotations
import argparse,json,subprocess
from pathlib import Path

def git(root,*args):
    r=subprocess.run(["git",*args],cwd=root,capture_output=True,text=True,timeout=10)
    return r.stdout.strip() if r.returncode==0 else None

def main():
 p=argparse.ArgumentParser();p.add_argument("repo");a=p.parse_args();root=Path(a.repo).resolve()
 checks={"is_cpython":(root/"Lib").is_dir() and (root/"Modules").is_dir() and (root/"Python").is_dir(),
         "head":git(root,"rev-parse","HEAD"),"branch":git(root,"branch","--show-current"),
         "status_porcelain":git(root,"status","--porcelain"),"upstream_main":git(root,"rev-parse","upstream/main"),
         "version":None}
 patch=root/"Include"/"patchlevel.h"
 if patch.exists():
  text=patch.read_text(errors="replace")
  import re
  m=re.search(r'#define\s+PY_VERSION\s+"([^"]+)"',text); checks["version"]=m.group(1) if m else None
 checks["clean_worktree"]=not bool(checks["status_porcelain"])
 checks["head_matches_upstream_main"]=bool(checks["head"] and checks["upstream_main"] and checks["head"]==checks["upstream_main"])
 print(json.dumps(checks,indent=2))
if __name__=="__main__":main()
