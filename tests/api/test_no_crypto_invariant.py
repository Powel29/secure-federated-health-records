"""Invariant tests: crypto stays in crypto_core (CONVENTIONS.md §2 rules 1, 2 & 10).

Rule 1: All primitives go through crypto_core. No module imports cryptography.hazmat
        directly except crypto_core itself.
Rule 2: Randomness comes from ``secrets``, never ``os.urandom`` or ``random``.
Rule 10: No cryptography in api/. The API layer orchestrates; it does not compute.
         If you are writing a cipher call in a route handler, it belongs in a module.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent.parent / "src"
API_DIR = SRC_DIR / "api"
CRYPTO_CORE_DIR = SRC_DIR / "crypto_core"


def _src_files_outside_crypto_core() -> list[Path]:
    return [
        path for path in SRC_DIR.rglob("*.py") if CRYPTO_CORE_DIR not in path.parents
    ]


def _imported_modules(tree: ast.AST) -> list[str]:
    modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
    return modules


def test_no_hazmat_imports_outside_crypto_core():
    """No module under src/ except crypto_core imports cryptography.hazmat (F24)."""
    files = _src_files_outside_crypto_core()
    assert files, "found no source files to scan"
    for py_file in files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for module in _imported_modules(tree):
            assert not module.startswith(
                "cryptography.hazmat"
            ), f"{py_file.relative_to(SRC_DIR)} violates Rule 1 by importing {module}"


def test_no_os_urandom_or_random_module_in_src():
    """Randomness in src/ comes only from ``secrets`` (F25, §2 rule 2)."""
    for py_file in SRC_DIR.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        assert "random" not in _imported_modules(
            tree
        ), f"{py_file.relative_to(SRC_DIR)} imports the random module"
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "urandom":
                raise AssertionError(
                    f"{py_file.relative_to(SRC_DIR)} calls urandom; use secrets"
                )


def test_no_direct_cipher_calls_in_api():
    """Verify that route handlers do not directly call cipher/crypto primitives."""
    forbidden_calls = {
        "aes_gcm_encrypt",
        "aes_gcm_decrypt",
        "hkdf_derive",
        "split_secret",
        "combine_shares",
        "encapsulate_key",
        "decapsulate_key",
        "reencrypt",
        # Review F33: these used to be called from api/ directly.
        "generate_emergency_key",
        "split_emergency_key",
        "derive_search_token",
        "sha256_digest",
        "decrypt_record",
        "open_delivery_package",
        "create_emergency_assertion",
        "unwrap_dek",
    }
    for py_file in API_DIR.glob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                func_name = ""
                if isinstance(func, ast.Name):
                    func_name = func.id
                elif isinstance(func, ast.Attribute):
                    func_name = func.attr

                assert func_name not in forbidden_calls, (
                    f"{py_file.name} violates Rule 10 by directly calling "
                    f"cipher primitive {func_name}()"
                )
