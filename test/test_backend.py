import pytest
from django.contrib.auth import get_user_model
from django.test import TestCase, RequestFactory, override_settings
from unittest.mock import Mock, patch, MagicMock
from auth0.backend import Auth0Backend


@pytest.mark.django_db
class Auth0BackendTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.backend = Auth0Backend()
        self.User = get_user_model()

    def _create_mock_token(self, user_info):
        """Helper to create a mock token with user_info"""
        return {"userinfo": user_info}

    def _create_mock_request(self):
        """Helper to create a mock request with session"""
        request = self.factory.get("/")
        request.session = {}
        return request

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_field_mapping_on_user_creation(self, mock_authorize):
        """Test that field mapping works when creating a new user"""
        user_info = {
            "sub": "auth0|123",
            "email": "test@example.com",
            "given_name": "John",
            "family_name": "Doe",
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        with override_settings(
            AUTH0_USER_FIELD_MAPPING={"first_name": "given_name", "last_name": "family_name"}
        ):
            user = self.backend.authenticate(request)

        self.assertIsNotNone(user)
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.email, "test@example.com")

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_field_mapping_updates_existing_user(self, mock_authorize):
        """Test that field mapping updates existing users on login"""
        # Create existing user with old data
        user = self.User.objects.create(
            username="auth0|123",
            email="old@example.com",
            first_name="OldFirst",
            last_name="OldLast",
        )

        user_info = {
            "sub": "auth0|123",
            "email": "new@example.com",
            "given_name": "NewFirst",
            "family_name": "NewLast",
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        with override_settings(
            AUTH0_USER_FIELD_MAPPING={"first_name": "given_name", "last_name": "family_name"}
        ):
            updated_user = self.backend.authenticate(request)

        user.refresh_from_db()
        self.assertEqual(user.first_name, "NewFirst")
        self.assertEqual(user.last_name, "NewLast")
        self.assertEqual(user.email, "new@example.com")

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_email_always_syncs(self, mock_authorize):
        """Test that email is always synced from Auth0, not just when None"""
        # Create existing user with email
        user = self.User.objects.create(
            username="auth0|123",
            email="old@example.com",
        )

        user_info = {
            "sub": "auth0|123",
            "email": "new@example.com",
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        self.backend.authenticate(request)

        user.refresh_from_db()
        self.assertEqual(user.email, "new@example.com")

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_email_not_updated_if_same(self, mock_authorize):
        """Test that email is not updated if it hasn't changed"""
        # Create existing user
        user = self.User.objects.create(
            username="auth0|123",
            email="same@example.com",
        )

        user_info = {
            "sub": "auth0|123",
            "email": "same@example.com",
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        # Mock save to check if it's called
        with patch.object(self.User, "save") as mock_save:
            self.backend.authenticate(request)
            # Save should not be called since email is the same and user is already active
            mock_save.assert_not_called()

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_superuser_group_grants_superuser_access(self, mock_authorize):
        """Test that users in superuser group get superuser access"""
        user_info = {
            "sub": "auth0|admin",
            "email": "admin@example.com",
            "groups": ["admins", "users"],
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        with override_settings(AUTH0_SUPERUSER_GROUP="admins"):
            user = self.backend.authenticate(request)

        self.assertTrue(user.is_superuser)

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_staff_group_grants_staff_access(self, mock_authorize):
        """Test that users in staff group get staff access"""
        user_info = {
            "sub": "auth0|staff",
            "email": "staff@example.com",
            "groups": ["staff", "users"],
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        with override_settings(AUTH0_STAFF_GROUP="staff"):
            user = self.backend.authenticate(request)

        self.assertTrue(user.is_staff)

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_superuser_access_removed_when_not_in_group(self, mock_authorize):
        """Test that superuser access is removed when user is no longer in group"""
        # Create existing superuser
        user = self.User.objects.create(
            username="auth0|admin",
            email="admin@example.com",
            is_superuser=True,
        )

        # User is no longer in admins group
        user_info = {
            "sub": "auth0|admin",
            "email": "admin@example.com",
            "groups": ["users"],  # Not in admins anymore
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        with override_settings(AUTH0_SUPERUSER_GROUP="admins"):
            self.backend.authenticate(request)

        user.refresh_from_db()
        self.assertFalse(user.is_superuser)

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_staff_access_removed_when_not_in_group(self, mock_authorize):
        """Test that staff access is removed when user is no longer in group"""
        # Create existing staff user
        user = self.User.objects.create(
            username="auth0|staff",
            email="staff@example.com",
            is_staff=True,
        )

        # User is no longer in staff group
        user_info = {
            "sub": "auth0|staff",
            "email": "staff@example.com",
            "groups": ["users"],  # Not in staff anymore
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        with override_settings(AUTH0_STAFF_GROUP="staff"):
            self.backend.authenticate(request)

        user.refresh_from_db()
        self.assertFalse(user.is_staff)

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_custom_groups_field(self, mock_authorize):
        """Test that custom groups field can be configured"""
        user_info = {
            "sub": "auth0|user",
            "email": "user@example.com",
            "roles": ["admin"],  # Using 'roles' instead of 'groups'
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        with override_settings(
            AUTH0_GROUPS_FIELD="roles", AUTH0_SUPERUSER_GROUP="admin"
        ):
            user = self.backend.authenticate(request)

        self.assertTrue(user.is_superuser)

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_groups_field_handles_single_string(self, mock_authorize):
        """Test that groups field handles single string (not a list)"""
        user_info = {
            "sub": "auth0|user",
            "email": "user@example.com",
            "groups": "admin",  # Single string instead of list
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        with override_settings(AUTH0_SUPERUSER_GROUP="admin"):
            user = self.backend.authenticate(request)

        self.assertTrue(user.is_superuser)

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_no_groups_field_in_user_info(self, mock_authorize):
        """Test that missing groups field doesn't cause errors"""
        user_info = {
            "sub": "auth0|user",
            "email": "user@example.com",
            # No groups field
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        with override_settings(
            AUTH0_SUPERUSER_GROUP="admin", AUTH0_STAFF_GROUP="staff"
        ):
            user = self.backend.authenticate(request)

        self.assertIsNotNone(user)
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.is_staff)

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_field_mapping_with_missing_auth0_field(self, mock_authorize):
        """Test that field mapping handles missing Auth0 fields gracefully"""
        user_info = {
            "sub": "auth0|user",
            "email": "user@example.com",
            "given_name": "John",
            # No family_name field
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        with override_settings(
            AUTH0_USER_FIELD_MAPPING={"first_name": "given_name", "last_name": "family_name"}
        ):
            user = self.backend.authenticate(request)

        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "")  # Should remain empty string since not in user_info

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_inactive_user_becomes_active(self, mock_authorize):
        """Test that inactive users become active on login"""
        # Create inactive user
        user = self.User.objects.create(
            username="auth0|user",
            email="user@example.com",
            is_active=False,
        )

        user_info = {
            "sub": "auth0|user",
            "email": "user@example.com",
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        self.backend.authenticate(request)

        user.refresh_from_db()
        self.assertTrue(user.is_active)

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_combined_field_mapping_and_permissions(self, mock_authorize):
        """Test that field mapping and permissions work together"""
        user_info = {
            "sub": "auth0|admin",
            "email": "admin@example.com",
            "given_name": "Admin",
            "family_name": "User",
            "groups": ["admins", "staff"],
        }
        mock_authorize.return_value = self._create_mock_token(user_info)
        request = self._create_mock_request()

        with override_settings(
            AUTH0_USER_FIELD_MAPPING={"first_name": "given_name", "last_name": "family_name"},
            AUTH0_SUPERUSER_GROUP="admins",
            AUTH0_STAFF_GROUP="staff",
        ):
            user = self.backend.authenticate(request)

        self.assertEqual(user.first_name, "Admin")
        self.assertEqual(user.last_name, "User")
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)

    @patch("auth0.backend.oauth.auth0.authorize_access_token")
    def test_session_stores_token_and_user_info(self, mock_authorize):
        """Test that token and user_info are stored in session"""
        user_info = {
            "sub": "auth0|user",
            "email": "user@example.com",
        }
        token = self._create_mock_token(user_info)
        mock_authorize.return_value = token
        request = self._create_mock_request()

        self.backend.authenticate(request)

        self.assertEqual(request.session["token"], token)
        self.assertEqual(request.session["user"], user_info)

    def test_get_user_returns_existing_user(self):
        """Test that get_user returns existing user by ID"""
        user = self.User.objects.create(
            username="auth0|user",
            email="user@example.com",
        )

        retrieved_user = self.backend.get_user(user.pk)
        self.assertEqual(retrieved_user, user)

    def test_get_user_returns_none_for_nonexistent_user(self):
        """Test that get_user returns None for nonexistent user"""
        retrieved_user = self.backend.get_user(99999)
        self.assertIsNone(retrieved_user)
