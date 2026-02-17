from setuptools import setup, find_packages

setup(
    name="sentinel-cli",
    version="1.0.0",
    description="Sentinel local CLI client (signed requests)",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=["requests", "python-dotenv"],
    entry_points={
        "console_scripts": [
            "sentinel=sentinel_cli_pkg.__main__:main",
        ],
    },
)
