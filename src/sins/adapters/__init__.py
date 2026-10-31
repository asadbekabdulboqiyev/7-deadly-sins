from .base import Adapter, ScanContext
from .nuclei import NucleiAdapter
from .osv import OsvAdapter

# Faqat shu adapterlar mavjud. Har biri o'z "gunoh"iga mos keladi.
REGISTRY: dict[str, Adapter] = {
    "nuclei": NucleiAdapter(),
    "osv": OsvAdapter(),
}

__all__ = ["REGISTRY", "Adapter", "ScanContext", "NucleiAdapter", "OsvAdapter"]
