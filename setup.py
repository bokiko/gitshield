from setuptools import setup, find_packages

setup(
    name="gitshield",
    version="0.1.0",
    description="Prevent accidental secret commits",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0",
    ],
    entry_points={
        "console_scripts": [
            "gitshield=gitshield.cli:main",
        ],
    },
)
