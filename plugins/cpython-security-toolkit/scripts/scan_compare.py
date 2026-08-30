"""Compare two CPython checkouts and report only findings introduced in target.

This is the primary guard against the "finding is already fixed in main" failure
mode.  A scanner may still recognize a historical code shape in both trees; the
comparison layer classifies that as UNCHANGED instead of a new finding.
"""
from __future__ import annotations
import argparse, importlib.util, json, os, sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
ENGINES={
 "archive":["scan_traversal.py","scan_symlink.py"],
 "protocol":["scan_validation_coverage.py","scan_incomplete_fix.py"],
 "resource":["scan_decompression_bounds.py","scan_negative_offset.py","scan_cpu_complexity.py"],
 "audit":["scan_audit_hooks.py"],
}

def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/name)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod

def run_engine(mod, root):
    if hasattr(mod,"scan"):
        # incomplete-fix has the same signature but scans repo root rather than Lib.
        return mod.scan(root)
    return []

def collect(root, engines):
    lib=os.path.join(root,"Lib")
    out=[]
    for engine in engines:
        for script in ENGINES[engine]:
            mod=load(script)
            target=root if script=="scan_incomplete_fix.py" else lib
            try: out.extend(run_engine(mod,target))
            except Exception as exc:
                out.append({"domain":engine.upper(),"module":"<engine>","function":script,"issue":"Engine error","confidence":"ANALYSIS-ERROR","evidence":repr(exc)})
    return out

def key(f):
    if f.get("fingerprint"): return f["fingerprint"]
    # Reuse the common helper when older engines don't attach fingerprints.
    try:
        common=load("common.py"); return common.fingerprint(f)
    except Exception:
        return "|".join(str(f.get(x,"")) for x in ("domain","sub_invariant","module","function","issue"))

def main():
    p=argparse.ArgumentParser(); p.add_argument("baseline"); p.add_argument("target"); p.add_argument("--engines",nargs="+",choices=ENGINES,default=list(ENGINES)); p.add_argument("--json-out"); args=p.parse_args()
    base=collect(args.baseline,args.engines); tgt=collect(args.target,args.engines)
    base_keys={key(x) for x in base if x.get("confidence") not in {"ANALYSIS-ERROR"}}
    new=[]; unchanged=[]
    for f in tgt:
        if key(f) in base_keys:
            f["novelty"] = "UNCHANGED"
            unchanged.append(f)
        else:
            f["novelty"] = "NEW"
            new.append(f)
    report={"baseline":os.path.abspath(args.baseline),"target":os.path.abspath(args.target),"new_findings":new,"unchanged_findings":unchanged,
            "summary":{"baseline":len(base),"target":len(tgt),"new":len(new),"unchanged":len(unchanged)}}
    text=json.dumps(report,indent=2)
    if args.json_out: Path(args.json_out).write_text(text+"\n",encoding="utf-8")
    print(text)
    print(f"NEW={len(new)} UNCHANGED={len(unchanged)}",file=sys.stderr)

if __name__=="__main__": main()
