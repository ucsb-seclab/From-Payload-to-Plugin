from setuptools import setup, find_packages

setup(
    name="scan-cli",
    version="0.1.0",
    description="CLI for managing the scanning tool",
    author="Your Name",
    author_email="ammonia@seclab",
    url="http://blabla.ammonia.xyz",
    packages=find_packages(),
    install_requires=[
        "click",
        "redis",
        "tabulate",
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "scanctr = scanctr.cli:cli"
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
