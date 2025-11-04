from django.conf import settings
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

        # Ensure the user is active and update fields from Auth0
        # Batch all potential updates to the user model here
        update_fields: list[str] = []

        if not user.is_active:
            user.is_active = True
            update_fields = ["is_active"]

        # Always update email if provided in user_info
        if "email" in user_info:
            new_email = user_info["email"]
            if user.email != new_email:
                user.email = new_email
                update_fields.append("email")

        # Process custom field mappings from AUTH0_USER_FIELD_MAPPING
        # Format: {'user_field': 'auth0_field'}
        # Example: {'first_name': 'given_name', 'field_foo': 'field_bar'}
        field_mapping = getattr(settings, "AUTH0_USER_FIELD_MAPPING", {})
        for user_field, auth0_field in field_mapping.items():
            if auth0_field in user_info:
                new_value = user_info[auth0_field]
                current_value = getattr(user, user_field, None)
                if current_value != new_value:
                    setattr(user, user_field, new_value)
                    if user_field not in update_fields:
                        update_fields.append(user_field)

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
