# Copyright (c) 2015, Menno Smits
# Released subject to the New BSD License
# Please see http://en.wikipedia.org/wiki/BSD_licenses

"""Pytest configuration for imapclient tests.

Loads environment variables from ``deps/aioimaplib/.env`` so that live
async integration tests can find Fastmail credentials without manual
``export`` steps.
"""

import pathlib

_ENV_FILE = pathlib.Path(__file__).resolve().parents[1] / "deps" / "aioimaplib" / ".env"

if _ENV_FILE.is_file():
    try:
        from dotenv import load_dotenv

        load_dotenv(_ENV_FILE)
    except ModuleNotFoundError:
        pass  # python-dotenv not installed; credentials must be set manually
