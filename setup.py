"""
Attack Forecasting — Package Setup
SIH Problem Statement #26153

Installs the project as an editable package so that `src` and `app`
can be imported from any working directory.

Usage:
    pip install -e .
"""

from setuptools import setup, find_packages
from pathlib import Path

long_description = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="attack-forecasting",
    version="1.0.0",
    description="AI Network Attack Forecasting using Causal World Models (SIH PS #26153)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Attack Forecasting Team",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests*", "scripts*", "data*", "models*", "results*"]),
    install_requires=[
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        "scipy>=1.10.0",
        "pyarrow>=12.0.0",
        "scikit-learn>=1.3.0",
        "torch>=2.0.0",
        "joblib>=1.3.0",
        "matplotlib>=3.7.0",
        "seaborn>=0.12.0",
    ],
    extras_require={
        "full": [
            "xgboost>=2.0.0",
            "imbalanced-learn>=0.11.0",
            "shap>=0.42.0",
            "scapy>=2.5.0",
            "plotly>=5.14.0",
            "streamlit>=1.25.0",
            "tqdm>=4.65.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "attack-forecasting-server=run_server:main",
            "attack-forecasting-train=train:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
    ],
)
