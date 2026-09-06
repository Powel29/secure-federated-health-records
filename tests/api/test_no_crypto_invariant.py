"""Invariant test: no direct cryptography in src/api (CONVENTIONS.md rules 1 & 10).

Rule 1: All primitives go through crypto_core. No module imports cryptography.hazmat
        directly except crypto_core itself.
Rule 10: No cryptography in api/. The API layer orchestrates; it does not compute.
         If you are writing a cipher call in a route handler, it belongs in a module.
"""

from __future__ import annotations

import ast
from pathlib import Path

API_DIR = Path(__file__).resolve().parent.parent.parent / "src" / "api"


def test_no_hazmat_imports_in_api():
    """Verify that no file in src/api imports cryptography.hazmat directly."""
    for py_file in API_DIR.glob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(
                        "cryptography.hazmat"
                    ), f"{py_file.name} violates Rule 1 by importing {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert not module.startswith(
                    "cryptography.hazmat"
                ), f"{py_file.name} violates Rule 1 by importing from {module}"


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
