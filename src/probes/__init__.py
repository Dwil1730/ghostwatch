import pkgutil
import importlib
import os

def load_probes():
    """
    Auto-import all probe modules so decorators register them.
    """
    package_dir = os.path.dirname(__file__)

    for _, module_name, _ in pkgutil.iter_modules([package_dir]):
        if module_name not in ["base", "registry"]:
            importlib.import_module(f"src.probes.{module_name}")
