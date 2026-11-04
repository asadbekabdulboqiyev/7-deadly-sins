from .base import Adapter, ScanContext
from .envy import EnvyAdapter
from .gluttony import GluttonyAdapter
from .lust import LustAdapter
from .nuclei import NucleiAdapter
from .osv import OsvAdapter
from .pride import PrideAdapter
from .wrath import WrathAdapter

# Adapter REGISTRY. Each adapter maps to its own "sin".
REGISTRY: dict[str, Adapter] = {
    "nuclei": NucleiAdapter(),
    "osv": OsvAdapter(),
    "pride": PrideAdapter(),
    "envy": EnvyAdapter(),
    "lust": LustAdapter(),
    "gluttony": GluttonyAdapter(),
    "wrath": WrathAdapter(),
}

__all__ = [
    "REGISTRY",
    "Adapter",
    "EnvyAdapter",
    "GluttonyAdapter",
    "LustAdapter",
    "NucleiAdapter",
    "OsvAdapter",
    "PrideAdapter",
    "WrathAdapter",
    "ScanContext",
]
