from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path


def load_strongbox():
    path = Path(__file__).resolve().parents[1] / "strongbox"
    loader = SourceFileLoader("strongbox_module", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module
