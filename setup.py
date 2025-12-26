from setuptools import setup, find_packages

setup(
    name="gitshield",
    version="0.3.0",
    description="Prevent accidental secret commits",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0",
        "requests>=2.28",
        "resend>=0.5",
    ],
    entry_points={
        "console_scripts": [
            "gitshield=gitshield.cli:main",
        ],
    },
)
