import os

# Set Django settings module before importing Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sample.settings")

# Set required Auth0 environment variables for tests (will be overridden in CI)
os.environ.setdefault("AUTH0_CLIENT_ID", "test-client-id")
os.environ.setdefault("AUTH0_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("AUTH0_DOMAIN", "test.auth0.com")
os.environ.setdefault("AUTH0_AUDIENCE", "test-audience")

