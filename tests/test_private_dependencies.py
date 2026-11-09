import builtins
import importlib
import logging.handlers
import sys

import pytest


@pytest.fixture
def watchdog(tmp_path, monkeypatch):
    handler = logging.handlers.RotatingFileHandler
    monkeypatch.setattr(logging.handlers, "RotatingFileHandler",
                        lambda *args, **kwargs: handler(tmp_path / "watchdog.log"))
    original_path = sys.path[:]
    sys.modules.pop("blacklist_watchdog", None)
    module = importlib.import_module("blacklist_watchdog")
    yield module
    module.logger.removeHandler(module.fh)
    module.logger.removeHandler(module.sh)
    module.fh.close()
    sys.path[:] = original_path
    sys.modules.pop("blacklist_watchdog", None)


@pytest.fixture
def missing_private_modules(monkeypatch):
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name in {"config", "market", "price_feed"}:
            raise ModuleNotFoundError(f"No module named '{name}'", name=name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)


def test_detector_import(missing_private_modules):
    with pytest.raises(ImportError, match="config.*private"):
        importlib.import_module("manipulation_detector")


@pytest.mark.parametrize("dry_run", [False, True])
def test_watchdog_startup(watchdog, missing_private_modules, dry_run):
    with pytest.raises(SystemExit, match="market.*--no-sell"):
        watchdog.run(dry_run=dry_run)
