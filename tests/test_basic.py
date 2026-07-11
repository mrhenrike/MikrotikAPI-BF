import importlib


def test_import_mikrotikapi_bf():
    m = importlib.import_module("mikrotikapi_bf")
    assert m is not None
