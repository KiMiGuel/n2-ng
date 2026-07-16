from setuptools import find_packages, setup


setup(
    name="n2-ng",
    version="0.1.0",
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
