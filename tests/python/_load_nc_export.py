"""Loads scripts/nc-export.py as an importable module.

The script's filename is not a valid Python module identifier (it has a
hyphen), so it can't be `import`ed directly -- this loads it via
importlib.util instead. Loading does not execute main(): the script
guards that behind `if __name__ == "__main__"`, and the loaded module's
__name__ is "nc_export", not "__main__".
"""
import importlib.util
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
NC_EXPORT_PATH = REPO_ROOT / "scripts" / "nc-export.py"


def load_nc_export():
    spec = importlib.util.spec_from_file_location("nc_export", NC_EXPORT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
