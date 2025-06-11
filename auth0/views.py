import logging
from urllib.parse import quote_plus, urlencode

from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.shortcuts import redirect, render, reverse

logger = logging.getLogger(__name__)

oauth = OAuth()

oauth.register(
    "auth0",
    client_id=settings.AUTH0_CLIENT_ID,
    client_secret=settings.AUTH0_CLIENT_SECRET,
    client_kwargs={
        "scope": getattr(settings, "AUTH0_SCOPES", "openid profile email"),
    },
    server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration",
)


def get_callback_uri(request):
    """
    Get the callback URI to send to Auth0.
    Can be configured via AUTH0_CALLBACK_URI setting.
    Defaults to the auth0_callback URL.
    """
    callback_uri_name = getattr(settings, "AUTH0_CALLBACK_URI", "auth0_callback")

    # If it's a URL name (default behavior)
    if callback_uri_name in ["auth0_callback", "auth0"]:
        return request.build_absolute_uri(reverse(callback_uri_name))

    # If it's a custom path, build the full URI
    if callback_uri_name.startswith("/"):
        return request.build_absolute_uri(callback_uri_name)

    # If it's already a full URI, return as-is
    if callback_uri_name.startswith("http"):
        return callback_uri_name

    # Default fallback
    return request.build_absolute_uri(reverse("auth0_callback"))


def login(request):
    if next_url := request.GET.get("next_url"):
        # store this in the sessino
        request.session["next_url"] = next_url
    return oauth.auth0.authorize_redirect(
        request,
        # this is our callback
        get_callback_uri(request),
        audience=settings.AUTH0_AUDIENCE,
    )


def logout(request):
    request.session.clear()

    return redirect(
        f"https://{settings.AUTH0_DOMAIN}/v2/logout?"
        + urlencode(
            {
                "returnTo": get_callback_uri(request),
                "client_id": settings.AUTH0_CLIENT_ID,
            },
            quote_via=quote_plus,
        ),
    )


def callback(request):
    """
    Index is both our landing URL and our de-facto auth0 callback.

    There are a few paths:
    1. If we have a code, we'll attempt to log in the user (and redirect to next_url or go into next flow).
    2. If we have a user already logged in, we can send them to next_url (or to a landing page).
    3. If we don't have a code or a user, show a login button.
    """
    # path (3) above
    if request.GET.get("code") is None and request.session.get("user") is None:
        logger.info("We have no code or user session, show login screen")
        # this would send them over to index so they could refresh the page...
        # we need to get them off of the "callback" url
        if "callback" in request.path:
            return redirect(reverse("auth0"))
        render(request, "django_auth0_auth/index.html")
    # path (1) above, we have code
    # Don't care whether there is a user or not
    elif request.GET.get("code") is not None:
        logger.info("We have a code, operating as the callback and logging that user in")
        logger.info(f"The request user looks like {request.user}")
        # Authenticate the user using the custom authentication backend
        user = authenticate(request)
        if user is None:
            # Handle authentication failure
            return redirect("login")  # Redirect to login page or show an error

        logger.info(f"The request user looks like {request.user}")

        # Log the user in
        auth_login(request, user)

        logger.info(f"The request user looks like {request.user}")

        # check the session for a next_url
        next_url = request.session.get("next_url")
        print(next_url)
        if next_url:
            # redirect to the next url
            logger.info("Redirecting to next_url")
            return redirect(next_url)
        # if we didn't redirect,
        # we'll fall out to path (2)
    # there is no code, so we know there is a user already
    # get the user for path (2)
    else:
        logger.info("We don't have a code but we do have a request user")
        logger.info(f"The request user looks like {request.user}")
        # get the customer from the db
        logger.info(f"The request session's user looks like {request.session.get('user')}")
        # userinfo = request.session.get("user")
        # user = Customer.objects.get(customerId=userinfo['sub'])
        user = request.user

    if "callback" in request.path:
        return redirect(reverse("auth0"))
    return render(request, "django_auth0_auth/index.html")
