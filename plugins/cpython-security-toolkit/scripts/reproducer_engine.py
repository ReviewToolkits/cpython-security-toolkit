"""Generate and validate conservative security reproducers.

A reproducer is CONFIRMED only when it emits an explicit machine-readable
``RESULT: VIOLATION`` marker.  Source inspection alone can never upgrade a
candidate to SECURITY.  A target CPython interpreter can be supplied with
``--python`` so tests are not accidentally run against the host Python.
"""
from __future__ import annotations
import argparse,json,os,subprocess,sys,tempfile,textwrap
from pathlib import Path

TEMPLATES={
"2a":textwrap.dedent('''\
from http.cookies import Morsel
m=Morsel()
try:
    m.update({"value":"ok\\r\\nInjected: yes"})
except Exception:
    print("RESULT: SAFE")
else:
    print("RESULT: VIOLATION")
'''),
"1b":textwrap.dedent('''\
import io, os, tarfile, tempfile
with tempfile.TemporaryDirectory() as root:
    dest=os.path.join(root,"dest"); os.mkdir(dest)
    outside=os.path.join(root,"outside"); os.mkdir(outside)
    archive=os.path.join(root,"x.tar")
    with tarfile.open(archive,"w") as t:
        link=tarfile.TarInfo("link"); link.type=tarfile.SYMTYPE; link.linkname=outside; t.addfile(link)
        data=b"marker"; f=tarfile.TarInfo("link/pwned.txt"); f.size=len(data); t.addfile(f,io.BytesIO(data))
    try:
        with tarfile.open(archive) as t: t.extractall(dest)
    except Exception:
        pass
    if os.path.exists(os.path.join(outside,"pwned.txt")):
        print("RESULT: VIOLATION")
    else:
        print("RESULT: SAFE")
'''),
"3a":textwrap.dedent('''\
# 3a requires a target-specific dynamic decompression test; no static source
# inspection is treated as confirmation.
print("RESULT: UNCONFIRMED")
'''),
"4a":textwrap.dedent('''\
# The dedicated code-opening policy must be checked on the target interpreter.
# A generic open() event is not equivalent to io.open_code().
import io, sys, tempfile, os
seen=[]
sys.addaudithook(lambda event,args: seen.append(event))
fd,path=tempfile.mkstemp(suffix=".pyc"); os.close(fd)
try:
    with io.open_code(path): pass
    print("RESULT: SAFE" if "open_code" in seen else "RESULT: UNCONFIRMED")
finally: os.unlink(path)
''')}

def select_template(f):
    sub=f.get("sub_invariant","")
    return TEMPLATES.get(sub)

def run(script,python_exe,timeout=30):
    with tempfile.NamedTemporaryFile("w",suffix=".py",delete=False,encoding="utf8") as f:
        f.write(script); path=f.name
    try:
        try:r=subprocess.run([python_exe,path],capture_output=True,text=True,timeout=timeout)
        except subprocess.TimeoutExpired:return {"status":"TIMEOUT","output":"","error":"timeout"}
        return {"status":"RAN","returncode":r.returncode,"output":r.stdout,"error":r.stderr}
    finally:
        os.unlink(path)

def classify(r):
    if r["status"]=="TIMEOUT":return "UNCONFIRMED"
    if r["status"]!="RAN" or r.get("returncode")!=0:return "UNCONFIRMED"
    lines={x.strip() for x in r.get("output","").splitlines()}
    if "RESULT: VIOLATION" in lines:return "CONFIRMED"
    if "RESULT: SAFE" in lines:return "NOT_REPRODUCED"
    return "UNCONFIRMED"

def main():
    p=argparse.ArgumentParser();p.add_argument("finding_json");p.add_argument("--dry-run",action="store_true");p.add_argument("--python",default=sys.executable);args=p.parse_args()
    f=json.load(sys.stdin) if args.finding_json=="-" else json.loads(Path(args.finding_json).read_text())
    script=select_template(f)
    if not script:
        print(json.dumps({"status":"NO_TEMPLATE","confidence_update":"SECURITY-CANDIDATE"},indent=2));return
    if args.dry_run:r={"status":"DRY_RUN","output":"","error":""}
    else:r=run(script,args.python)
    status=classify(r)
    mapping={"CONFIRMED":"SECURITY","NOT_REPRODUCED":"FALSE-POSITIVE","UNCONFIRMED":"SECURITY-CANDIDATE","DRY_RUN":f.get("confidence","SECURITY-CANDIDATE")}
    print(json.dumps({"finding_id":f.get("domain","UNK"),"reproducer_status":status,"confidence_update":mapping[status],"script":script,"run_output":r.get("output",""),"run_error":r.get("error","")},indent=2))
if __name__=="__main__":main()
