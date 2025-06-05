from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

from .views import oauth


class Auth0Backend(BaseBackend):
    def authenticate(self, request):
        # handle the token validation here
        token = oauth.auth0.authorize_access_token(request)

        # Process the token and get user info
        user_info = self.get_user_info(token)
        if not user_info:
            return None

        request.session["token"] = token
        request.session["user"] = user_info

        # Get the custom user model
        User = get_user_model()

        # Here you would typically create or get the user from your database
        user, created = User.objects.get_or_create(
            **{
                User.USERNAME_FIELD: user_info["sub"],
                "defaults": {"is_active": True},
            }
        )
        print(f"user was {created=}")

        # Ensure the user is active
        if not user.is_active:
            user.is_active = True
            user.save()

        return user

    def get_user_info(self, token):
        # Assuming token is already authorized and contains userinfo
        return token.get("userinfo")

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
