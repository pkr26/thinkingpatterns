"""MindPattern backend package."""

# Single source for the app version inside the code (pyproject.toml carries
# the same value for packaging; importlib.metadata is unusable because the
# package is never installed — the image and dev venv run from source).
__version__ = "1.0.0"
