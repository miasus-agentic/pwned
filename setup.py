from setuptools import setup, find_packages

setup(
    name="pwned-cli",
    version="1.0.0",
    description="CLI tool to check if emails/passwords have been exposed in data breaches",
    author="pwned-cli contributors",
    license="MIT",
    packages=find_packages(),
    entry_points={"console_scripts": ["pwned=pwned.cli:main"]},
    python_requires=">=3.7",
)
