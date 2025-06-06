import os
import pytest
import time
from contextlib import contextmanager
from subprocess import Popen, run
from http.client import HTTPConnection
from playwright.sync_api import Page, expect
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()


@pytest.fixture(autouse=True)
def setup_env():
    """Ensure required environment variables are available"""
    required_vars = ["AUTH0_USERNAME", "AUTH0_PASSWORD"]
    for var in required_vars:
        if not os.getenv(var):
            pytest.skip(f"Environment variable {var} not set")


def django_cli(*args: str) -> None:
    """Run Django management commands"""
    run(
        ["python3", "manage.py"] + list(args),
        cwd=".",
        env=os.environ,
    )


@contextmanager
def django_server(port: int = 8000):
    """Context manager to run Django server in background"""
    print(f"Starting Django server on port {port}")
    
    # Run migrations first
    django_cli("migrate")
    
    # Start server
    cmd = ["python3", "manage.py", "runserver", str(port)]
    process = Popen(cmd, cwd=".", env=os.environ)
    
    # Wait for server to be ready
    retries = 20
    time.sleep(2)  # Initial wait
    
    while retries > 0:
        conn = HTTPConnection(f"localhost:{port}")
        try:
            conn.request("HEAD", "/auth0/")
            response = conn.getresponse()
            if response is not None:
                print(f"Django server is ready on port {port}")
                yield process
                break
        except ConnectionRefusedError:
            print(f"Waiting for Django server... {retries} retries left")
            time.sleep(1)
            retries -= 1
    
    if not retries:
        raise RuntimeError(f"Failed to start Django server on port {port}")
    
    # Clean up
    print("Terminating Django server")
    process.terminate()
    time.sleep(1)
    process.terminate()


@pytest.fixture(scope="session")
def running_server():
    """Session-scoped fixture to run Django server"""
    with django_server(8000) as server:
        yield server


@pytest.mark.e2e
def test_auth0_login_flow(page: Page, running_server):
    """Test the complete Auth0 login flow"""
    # Get credentials from environment
    username = os.getenv("AUTH0_USERNAME")
    password = os.getenv("AUTH0_PASSWORD")
    
    # Navigate to the auth0 login page
    page.goto("http://localhost:8000/auth0/")
    
    # Verify initial page elements
    expect(page.get_by_role("heading", name="Auth0 Login")).to_be_visible()
    expect(page.get_by_role("button", name="Go to Login")).to_be_visible()
    
    # Click "Go to Login" to start the Auth0 flow
    page.get_by_role("button", name="Go to Login").click()
    
    # Wait for Auth0 login form to appear and fill credentials
    expect(page.get_by_role("textbox", name="Email address")).to_be_visible()
    page.get_by_role("textbox", name="Email address").fill(username)
    page.get_by_role("textbox", name="Password").fill(password)
    page.get_by_role("button", name="Continue", exact=True).click()
    
    # Verify successful login - should redirect back to our app
    expect(page.get_by_role("heading", name="Auth0 Login")).to_be_visible()
    expect(page.get_by_role("link", name="Logout")).to_be_visible()


@pytest.mark.e2e
def test_auth0_logout_flow(page: Page, running_server):
    """Test the Auth0 logout flow after login"""
    # First login (reuse login test logic)
    username = os.getenv("AUTH0_USERNAME")
    password = os.getenv("AUTH0_PASSWORD")
    
    page.goto("http://localhost:8000/auth0/")
    page.get_by_role("button", name="Go to Login").click()
    
    expect(page.get_by_role("textbox", name="Email address")).to_be_visible()
    page.get_by_role("textbox", name="Email address").fill(username)
    page.get_by_role("textbox", name="Password").fill(password)
    page.get_by_role("button", name="Continue", exact=True).click()
    
    # Verify we're logged in
    expect(page.get_by_role("link", name="Logout")).to_be_visible()
    
    # Click logout
    page.get_by_role("link", name="Logout").click()
    
    # Verify we're logged out - should see login button again
    expect(page.get_by_role("button", name="Go to Login")).to_be_visible()
