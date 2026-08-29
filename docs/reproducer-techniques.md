# Reproducer Techniques

Catalogue of reproducer approaches used for different security finding classes. Each technique produces a minimal, self-contained Python script that demonstrates the violated invariant.

---

## Technique 1: Crafted Archive — Path Traversal

**Sub-invariants:** 1a, 1b, 1c

**Approach:** Construct a tar or zip archive in-memory using the `tarfile` or `zipfile` module with entries containing the dangerous path component. Extract to a temporary directory and check whether any extracted file appears outside the destination.

**Template outline:**

```python
import io, os, tarfile, tempfile

with tempfile.TemporaryDirectory() as workdir:
    # Build the archive in-memory
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        sym = tarfile.TarInfo("escape_link")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "../../../../tmp"
        tar.addfile(sym)
        # ... add member following the symlink

    buf.seek(0)
    extract_dir = os.path.join(workdir, "output")
    os.makedirs(extract_dir)

    with tarfile.open(fileobj=buf) as tar:
        tar.extractall(extract_dir)

    # Check for escape
    ...
```

**Notes:**
- Use `tempfile.TemporaryDirectory()` to avoid leaving test artifacts
- The symlink target should be relative (`../../../../tmp`), not absolute, to avoid permission errors on most systems
- Check not just for file existence outside the dir, but also for symlink creation

---

## Technique 2: Cookie Value Injection — Assignment Path Coverage

**Sub-invariants:** 2a, 2d

**Approach:** Attempt to assign a control-character-containing value via each code path (`__setitem__`, `update()`, `|=`, unpickling). The primary path should reject it; any additional path that accepts it is a validation gap.

**Template outline:**

```python
from http.cookies import Morsel

PAYLOAD = "value\r\nInjected: evil"

for method_name, attempt in [
    ("__setitem__", lambda m: m.__setitem__("value", PAYLOAD)),
    ("update()",    lambda m: m.update({"value": PAYLOAD})),
    ("|=",          lambda m: m.__ior__({"value": PAYLOAD})),
]:
    m = Morsel()
    try:
        attempt(m)
        print(f"{method_name}: ACCEPTED — potential injection path")
    except Exception as e:
        print(f"{method_name}: REJECTED correctly")
```

---

## Technique 3: Decompression Amplification — Dry Run

**Sub-invariants:** 3a, 3b

**Approach (dry run):** Use AST inspection of the decompression module to check whether `.read()` is called with or without a size argument. Report the code path without actually allocating large memory.

**Template outline:**

```python
import ast, inspect, zipfile

source = inspect.getsource(zipfile.ZipExtFile.read)
tree = ast.parse(source)
unbounded = []
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        if hasattr(node.func, "attr") and node.func.attr == "read":
            if not node.args and not node.keywords:
                unbounded.append(node.lineno)
print(f"Unbounded reads at: {unbounded}")
```

**Approach (live, with caution):** For smaller amplification ratios (10× or less), generate a small highly-compressible input and measure peak RSS before and after. Do not attempt multi-GB allocation in automated tests.

---

## Technique 4: Audit Hook Comparison

**Sub-invariants:** 4a

**Approach:** Register a `sys.audit()` hook, load a Python file via `io.open_code()` (expected: hook fires), then load via plain `open()` (may not fire). Compare event counts.

**Notes:**
- `sys.addaudithook()` cannot be removed — use a subprocess for isolation
- The hook fires for `"open"` events, not `"io.open_code"` specifically
- Some audit events are only visible in debug builds

---

## Technique 5: Substitution-Before-Validation — Ordering Check

**Sub-invariants:** 2b, 4b

**Approach:** Construct a URL or command string containing a `%action` substitution placeholder that, after substitution, contains a dangerous character sequence. Call the function under test and observe whether the post-substitution form is validated.

**Template outline:**

```python
import webbrowser

# A URL that is benign before substitution but dangerous after
# (specific pattern depends on browser type)
# Test that the URL is validated at the right point in the pipeline
# ...
```

**Notes:**
- This technique is most useful as source-level analysis rather than dynamic testing
- The `substitution-ordering` agent uses AST-level call ordering, not dynamic testing
- A confirmed live reproducer requires knowing the specific `%action` pattern for the browser type

---

## Technique 6: Negative Offset — Infinite Loop Detection

**Sub-invariants:** 3c

**Approach:** Construct a tar archive with a negative offset in an entry header. Call the `tarfile._block()` or equivalent function and confirm that it either validates the input or enters an infinite loop.

**Notes:**
- Infinite loop detection requires a subprocess with a timeout
- The fixture should use a small negative value (e.g., `-1`) for quick confirmation
- Do not run infinite-loop tests in the main test suite without a timeout wrapper

---

## General Principles

1. **Self-contained.** No external dependencies beyond stdlib. No files left on disk.
2. **Deterministic.** Same input produces same output every run.
3. **Fast.** Under 5 seconds for the vast majority of techniques.
4. **Clear output.** Print "INVARIANT VIOLATED" or "correctly enforced" — not ambiguous output.
5. **Versioned.** Note which Python version the reproducer was confirmed on.
6. **Non-destructive.** No writes outside `tempfile.TemporaryDirectory()` scope. No network calls.
