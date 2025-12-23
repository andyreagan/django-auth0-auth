import base64
import json

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

from .views import oauth


class Auth0Backend(BaseBackend):
    # Override in subclass to map model fields to access token claims
    # Format: {"user_field": "access_token_claim_name"}
    # Example: {"member_id": "http://example.com/member_id"}
    ACCESS_TOKEN_CLAIM_MAPPING: dict[str, str] = {}

    def get_extra_defaults(self, token) -> dict:
        """Extract extra default values from the access token.

        Override this method in subclasses for custom claim extraction logic.
        Returns a dict of {user_field: value} to be used when creating/updating users.
        """
        # Get mapping from class attribute or settings
        claim_mapping = self.ACCESS_TOKEN_CLAIM_MAPPING or getattr(
            settings, "AUTH0_ACCESS_TOKEN_CLAIM_MAPPING", {}
        )

        if not claim_mapping:
            return {}

        # Decode the access token to extract claims
        access_token = token.get("access_token")
        if not access_token:
            return {}

        claims = self._decode_jwt_payload(access_token)
        if not claims:
            return {}

        # Map claims to user fields
        extra_defaults = {}
        for user_field, claim_name in claim_mapping.items():
            if claim_name in claims:
                extra_defaults[user_field] = claims[claim_name]

        return extra_defaults

    def _decode_jwt_payload(self, jwt_token: str) -> dict:
        """Decode the payload section of a JWT token without verification.

        The token has already been validated by Auth0 during the OAuth flow,
        so we only need to extract the claims from the payload.
        """
        try:
            # JWT format: header.payload.signature
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return {}

            # Decode the payload (second part)
            # Add padding if needed for base64 decoding
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding

            decoded = base64.urlsafe_b64decode(payload)
            return json.loads(decoded)
        except (ValueError, json.JSONDecodeError):
            return {}

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

        # Get extra defaults from access token claims
        extra_defaults = self.get_extra_defaults(token)

        # Build defaults dict for user creation
        defaults = {
            "is_active": True,
            "email": user_info.get("email"),
            **extra_defaults,
        }

        # Here you would typically create or get the user from your database
        user, created = User.objects.get_or_create(
            **{
                User.USERNAME_FIELD: user_info["sub"],
                "defaults": defaults,
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

        # Update fields from access token claims (extra_defaults)
        for user_field, new_value in extra_defaults.items():
            current_value = getattr(user, user_field, None)
            if current_value != new_value:
                setattr(user, user_field, new_value)
                if user_field not in update_fields:
                    update_fields.append(user_field)

        # Handle staff and superuser permissions based on Auth0 groups/roles
        # Get the field name that contains groups/roles (default: 'groups')
        groups_field = getattr(settings, "AUTH0_GROUPS_FIELD", "groups")
        user_groups = user_info.get(groups_field, [])

        # Ensure user_groups is a list
        if not isinstance(user_groups, list):
            user_groups = [user_groups] if user_groups else []

        # Check superuser group membership
        superuser_group = getattr(settings, "AUTH0_SUPERUSER_GROUP", None)
        if superuser_group:
            new_superuser_status = superuser_group in user_groups
            if user.is_superuser != new_superuser_status:
                user.is_superuser = new_superuser_status
                if "is_superuser" not in update_fields:
                    update_fields.append("is_superuser")

        # Check staff group membership
        staff_group = getattr(settings, "AUTH0_STAFF_GROUP", None)
        if staff_group:
            new_staff_status = staff_group in user_groups
            if user.is_staff != new_staff_status:
                user.is_staff = new_staff_status
                if "is_staff" not in update_fields:
                    update_fields.append("is_staff")

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
