from pathlib import Path
import re

from setuptools import find_packages, setup


def _read_version():
    init = Path(__file__).resolve().parent / "src" / "n2ng" / "__init__.py"
    text = init.read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.M)
    if not match:
        raise RuntimeError("Unable to find __version__ in src/n2ng/__init__.py")
    return match.group(1)


setup(
    name="n2-ng",
    version=_read_version(),
    description="Single-window GUI for the aircrack-ng suite",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="KiMiGuEL — INDEPENTEST",
    license="GPL-3.0-only",
    package_dir={"": "src"},
    packages=find_packages("src"),
    install_requires=["scapy"],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "n2-ng=n2ng.main:main",
        ],
    },
    classifiers=[
        "Environment :: X11 Applications",
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
)
