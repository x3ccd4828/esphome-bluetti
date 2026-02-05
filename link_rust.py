from pathlib import Path
import os
from typing import NoReturn

Import("env")


def fail(message: str) -> NoReturn:
    print(f"[link_rust.py] ERROR: {message}")
    raise RuntimeError(message)


def discover_workspace_root() -> Path:
    explicit = os.environ.get("BLUETTI_WORKSPACE")
    if explicit:
        root = Path(explicit)
        if not root.exists():
            fail(f"BLUETTI_WORKSPACE does not exist: {root}")
        return root

    project_dir = Path(env.subst("$PROJECT_DIR")).resolve()
    search_roots = [project_dir, *project_dir.parents, Path("/config")]
    seen = set()
    for root in search_roots:
        key = str(root)
        if key in seen:
            continue
        seen.add(key)
        if (root / "bluetti-encryption").exists():
            return root

    fail(
        "Unable to locate workspace root containing 'bluetti-encryption'. "
        "Set BLUETTI_WORKSPACE or BLUETTI_RUST_STATICLIB."
    )


rust_target = os.environ.get("BLUETTI_RUST_TARGET", "xtensa-esp32-none-elf")
rust_staticlib_override = os.environ.get("BLUETTI_RUST_STATICLIB")

if rust_staticlib_override:
    rust_staticlib = Path(rust_staticlib_override)
    rust_lib_dir = Path(os.environ.get("BLUETTI_RUST_LIB_DIR", str(rust_staticlib.parent)))
else:
    workspace_root = discover_workspace_root()
    rust_lib_dir = Path(
        os.environ.get(
            "BLUETTI_RUST_LIB_DIR",
            str(workspace_root / "bluetti-encryption" / "target" / rust_target / "release"),
        )
    )
    rust_staticlib = rust_lib_dir / "libbluetti_encryption.a"

if not rust_staticlib.exists():
    fail(
        "Rust static library not found for linking. "
        f"Expected: {rust_staticlib}. "
        "Prebuild it first and/or set BLUETTI_RUST_STATICLIB."
    )

print(f"[link_rust.py] Linking Rust static library: {rust_staticlib}")
env.Append(
    LIBPATH=[str(rust_lib_dir)],
    LIBS=["bluetti_encryption"],
)
