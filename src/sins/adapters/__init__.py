from .base import Adapter, ScanContext
from .envy import EnvyAdapter
from .nuclei import NucleiAdapter
from .osv import OsvAdapter
from .pride import PrideAdapter

# Adapterlar REGISTRY. Har biri o'z "gunoh"iga mos keladi.
REGISTRY: dict[str, Adapter] = {
    "nuclei": NucleiAdapter(),
    "osv": OsvAdapter(),
    "pride": PrideAdapter(),
    "envy": EnvyAdapter(),
}

__all__ = [
    "REGISTRY",
    "Adapter",
    "EnvyAdapter",
    "NucleiAdapter",
    "OsvAdapter",
    "PrideAdapter",
    "ScanContext",
]
