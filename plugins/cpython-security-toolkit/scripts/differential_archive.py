"""Runtime archive-boundary differential regression harness.

It exercises equivalent escape names through tar and zip and reports whether the
final write stayed inside the extraction directory. This complements static
analysis and is deliberately safe: every test uses a private TemporaryDirectory.
"""
from __future__ import annotations
import argparse,io,json,os,tempfile,zipfile,tarfile

def inside(base,path):
    return os.path.commonpath([os.path.realpath(base),os.path.realpath(path)])==os.path.realpath(base)

def run():
    cases=["../escape.txt","/absolute.txt","nested/../../escape.txt"]
    results=[]
    for kind in ("zip","tar"):
        for name in cases:
            with tempfile.TemporaryDirectory() as root:
                dest=os.path.join(root,"dest");os.mkdir(dest);archive=os.path.join(root,"a."+kind)
                if kind=="zip":
                    with zipfile.ZipFile(archive,"w") as z:z.writestr(name,b"x")
                    with zipfile.ZipFile(archive) as z:
                        try:z.extractall(dest)
                        except Exception:pass
                else:
                    with tarfile.open(archive,"w") as t:
                        b=b"x";i=tarfile.TarInfo(name);i.size=1;t.addfile(i,io.BytesIO(b))
                    with tarfile.open(archive) as t:
                        try:t.extractall(dest)
                        except Exception:pass
                escaped=os.path.join(root,"escape.txt")
                results.append({"format":kind,"member":name,"escaped":os.path.exists(escaped),"inside_check":inside(dest,escaped)})
    return results

def main():
 p=argparse.ArgumentParser();p.add_argument("--json",action="store_true");a=p.parse_args();r=run();print(json.dumps(r,indent=2) if a.json else "\n".join(f"{x['format']} {x['member']}: {'ESCAPED' if x['escaped'] else 'contained'}" for x in r));
if __name__=="__main__":main()
