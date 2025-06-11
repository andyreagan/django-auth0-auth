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
                "defaults": {
                    "is_active": True,
                    "email": user_info.get("email"),
                },
            }
        )
        print(f"user was {created=}")

        # Ensure the user is active and set email if we have it
        # Batch the two potential updates to the user model here
        update_fields: list[str] = []

        if not user.is_active:
            user.is_active = True
            update_fields = ["is_active"]

        if "email" in user_info and user.email is None:
            user.email = user_info["email"]
            update_fields.append("email")

        if len(update_fields) > 0:
            user.save(update_fields=update_fields)

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
