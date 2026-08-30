"""Detect genuinely unbounded decompressor output paths.

Static results are candidates only.  The scanner deliberately avoids treating a
normal file ``read()``/``readall()`` as decompression and understands the common
CPython ``self._decompressor`` indirection that caused earlier false positives.
"""
from __future__ import annotations

import ast, json, os, sys
from pathlib import Path
from typing import Optional
from common import add_fingerprint, read_ast

TARGET_MODULES = [
    "zipfile/__init__.py", "zipfile.py", "tarfile.py", "lzma.py", "bz2.py",
    "gzip.py", "plistlib.py", "zlib.py",
]
DECOMPRESSOR_NAMES = {"decompressor", "_decompressor", "decomp", "_decomp"}
DECOMPRESS_METHODS = {"decompress", "readall"}
ALLOCATIONS = {"bytes", "bytearray", "memoryview"}
METADATA_SIZES = {"file_size", "compress_size", "dict_size", "block_size", "data_size", "entry_size"}


def _receiver(node: ast.Call) -> str:
    if not isinstance(node.func, ast.Attribute):
        return ""
    value = node.func.value
    if isinstance(value, ast.Name):
        return value.id.lower()
    if isinstance(value, ast.Attribute):
        return value.attr.lower()
    return ""


def _bounded(call: ast.Call) -> bool:
    # decompress(data) is unbounded; decompress(data, max_length) is bounded.
    # read(size) is bounded, while readall() is not.
    if call.func.attr == "decompress":
        return len(call.args) >= 2 or any(k.arg in {"max_length", "size", "length", "n"} for k in call.keywords)
    if call.func.attr == "readall":
        return False
    return bool(call.args) or any(k.arg in {"size", "length", "n"} for k in call.keywords)


def scan_module(path: str) -> list[dict]:
    tree, source, error = read_ast(path)
    if error:
        return [{"domain":"RES", "module":Path(path).name, "function":"<parse error>",
                 "lineno":0, "issue":"Scanner could not parse source", "sub_invariant":"N/A",
                 "confidence":"ANALYSIS-ERROR", "evidence":error, "corpus_ref":None,
                 "invariant":"Invariant 3: Resource Amplification Bound"}]
    results = []
    current = "<module>"
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            current = node.name
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        name = node.func.attr
        recv = _receiver(node)
        if name in DECOMPRESS_METHODS and not _bounded(node):
            # readall is only relevant when the receiver is clearly a decompressor.
            clearly_decomp = recv in DECOMPRESSOR_NAMES or recv.endswith("decompressor")
            if name == "readall" and recv not in DECOMPRESSOR_NAMES:
                clearly_decomp = False
            if clearly_decomp:
                results.append(add_fingerprint({
                    "domain":"RES", "module":Path(path).name, "function":current,
                    "lineno":node.lineno,
                    "issue":"Decompressor output is requested without a max-length/size bound",
                    "sub_invariant":"3a", "confidence":"SECURITY-CANDIDATE",
                    "evidence":f"{recv}.{name}() at line {node.lineno} has no output bound. Receiver is explicitly named as a decompressor; verify runtime allocation and caller contract.",
                    "corpus_ref":"RES-005 (zipfile decompression amplification)",
                    "invariant":"Invariant 3: Resource Amplification Bound",
                }))
        if name in ALLOCATIONS and node.args and isinstance(node.args[0], ast.Attribute):
            if node.args[0].attr in METADATA_SIZES:
                results.append(add_fingerprint({
                    "domain":"RES", "module":Path(path).name, "function":current,
                    "lineno":node.lineno,
                    "issue":"Allocation uses archive metadata size without a statically visible bound",
                    "sub_invariant":"3b", "confidence":"SECURITY-CANDIDATE",
                    "evidence":f"{name}() consumes metadata field {node.args[0].attr!r} directly. This is a candidate; helper validation and format-level limits must be resolved before a verdict.",
                    "corpus_ref":"RES-004, RES-006",
                    "invariant":"Invariant 3: Resource Amplification Bound",
                }))
    return results


def scan(lib_dir: str) -> list[dict]:
    out=[]
    for rel in TARGET_MODULES:
        path=os.path.join(lib_dir, rel.replace("/", os.sep))
        if os.path.exists(path): out.extend(scan_module(path))
    return out

if __name__ == "__main__":
    if len(sys.argv)<2: raise SystemExit(f"Usage: {sys.argv[0]} <cpython-lib-dir>")
    results=scan(sys.argv[1]); print(json.dumps(results, indent=2)); print(f"Total: {len(results)}", file=sys.stderr)
