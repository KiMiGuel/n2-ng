"""N2-ng package."""

__version__ = "0.1.3"

__all__ = ["run", "__version__"]


def __getattr__(name):
    if name == "run":
        from .main import main

        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
