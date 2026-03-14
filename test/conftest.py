import os

import pytest

# Set Django settings module before importing Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sample.settings")

# Set required Auth0 environment variables for tests (will be overridden in CI)
os.environ.setdefault("AUTH0_CLIENT_ID", "test-client-id")
os.environ.setdefault("AUTH0_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("AUTH0_DOMAIN", "test.auth0.com")
os.environ.setdefault("AUTH0_AUDIENCE", "test-audience")


def pytest_collection_modifyitems(config, items):
    """Skip e2e playwright tests outside of CI (they require a live Auth0 tenant)."""
    if not os.environ.get("CI"):
        skip = pytest.mark.skip(reason="Playwright e2e tests only run in CI (set CI=1 to override)")
        for item in items:
            if "test_login" in item.nodeid or "test_logout" in item.nodeid:
                item.add_marker(skip)
