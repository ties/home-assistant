"""Home Assistant auth provider."""
import asyncio
from collections import OrderedDict
import logging

from typing import Any, Dict, Generator, List, Optional, Set, cast

import voluptuous as vol

from homeassistant.const import CONF_ID
from homeassistant.core import callback, HomeAssistant
from homeassistant.exceptions import InvalidAuth, InvalidUser

from . import AuthProvider, AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, LoginFlow

from ..models import Credentials, UserMeta
from ..util import hash_password, verify_password


STORAGE_VERSION = 1
STORAGE_KEY = "auth_provider.homeassistant"


"""Type of the user elements.

Semantically clearer than repeated dicts of same type."""
UserType = Dict[str, str]


def _disallow_id(conf: Dict[str, Any]) -> Dict[str, Any]:
    """Disallow ID in config."""
    if CONF_ID in conf:
        raise vol.Invalid("ID is not allowed for the homeassistant auth provider.")

    return conf


CONFIG_SCHEMA = vol.All(AUTH_PROVIDER_SCHEMA, _disallow_id)


class Data:
    """Hold the user data."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the user data store."""
        self.hass = hass
        self._store = hass.helpers.storage.Store(
            STORAGE_VERSION, STORAGE_KEY, private=True
        )
        self._data: Optional[Dict[str, Any]] = None
        # Legacy mode will allow usernames to start/end with whitespace
        # and will compare usernames case-insensitive.
        # Remove in 2020 or when we launch 1.0.
        self.is_legacy = False

    @callback
    def normalize_username(self, username: str) -> str:
        """Normalize a username based on the mode."""
        if self.is_legacy:
            return username

        return username.strip().casefold()

    def _find_user_by_name(self, username: str) -> Generator[UserType, None, None]:
        """Find all users that match the given name.

        Whiel this function iterates over all users, it will not be constant
        time: It depends on the number of loop bodies executed.

        Legacy mode is handled by normalize_username.

        Args:
            username (str): The username to look up.

        Yields:
            dict: The matching user object(s)

        Returns: None

        """
        # Normalize because we are comparing normalized usernames.
        username = self.normalize_username(username)

        for user in self.users:
            if self.normalize_username(user["username"]) == username:
                yield user

    async def async_load(self) -> None:
        """Load stored data."""
        data = await self._store.async_load()

        if data is None:
            data = {"users": []}

        seen: Set[str] = set()

        for user in data["users"]:
            username = user["username"]

            # check if we have duplicates
            folded = username.casefold()

            if folded in seen:
                self.is_legacy = True

                logging.getLogger(__name__).warning(
                    "Home Assistant auth provider is running in legacy mode "
                    "because we detected usernames that are case-insensitive"
                    "equivalent. Please change the username: '%s'.",
                    username,
                )

                break

            seen.add(folded)

            # check if we have unstripped usernames
            if username != username.strip():
                self.is_legacy = True

                logging.getLogger(__name__).warning(
                    "Home Assistant auth provider is running in legacy mode "
                    "because we detected usernames that start or end in a "
                    "space. Please change the username: '%s'.",
                    username,
                )

                break

        self._data = data

    @property
    def users(self) -> List[UserType]:
        """Return users."""
        return self._data["users"]  # type: ignore

    def validate_login(self, username: str, password: str) -> None:
        """Validate a username and password.

        Raises InvalidAuth if auth invalid.
        """
        pw_hash = None

        # Compare all users to avoid timing attacks.
        for user in self._find_user_by_name(username):
            pw_hash = user["password"]

        # handles empty hash and is constant time independent of existence of
        # hash.
        if not verify_password(password, pw_hash):
            raise InvalidAuth

    def add_auth(self, username: str, password: str) -> None:
        """Add a new authenticated user/pass."""
        # Explicitly normalize since we will use this exact string when adding.
        username = self.normalize_username(username)

        # Check whether user with given name already exists.
        if any(self._find_user_by_name(username)):
            raise InvalidUser

        self.users.append({"username": username, "password": hash_password(password)})

    @callback
    def async_remove_auth(self, username: str) -> None:
        """Remove authentication."""
        username = self.normalize_username(username)

        index = None
        for i, user in enumerate(self.users):
            if self.normalize_username(user["username"]) == username:
                index = i
                break

        if index is None:
            raise InvalidUser

        self.users.pop(index)

    def change_password(self, username: str, new_password: str) -> None:
        """Update the password.

        Raises InvalidUser if user cannot be found.
        """
        for user in self._find_user_by_name(username):
            user["password"] = hash_password(new_password)
            break
        else:
            raise InvalidUser

    async def async_save(self) -> None:
        """Save data."""
        await self._store.async_save(self._data)


@AUTH_PROVIDERS.register("webauthn")
class WebAuthnAuthProvider(AuthProvider):
    """Auth provider based on a local storage of users in HASS config dir."""

    DEFAULT_TITLE = "Home Assistant WebAuthn"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize an Home Assistant auth provider."""
        super().__init__(*args, **kwargs)
        self.data: Optional[Data] = None
        self._init_lock = asyncio.Lock()

    async def async_initialize(self) -> None:
        """Initialize the auth provider."""
        async with self._init_lock:
            if self.data is not None:
                return

            data = Data(self.hass)
            await data.async_load()
            self.data = data

    async def async_login_flow(self, context: Optional[Dict]) -> LoginFlow:
        """Return a flow to login."""
        return WebAuthnFlow(self)

    async def async_validate_login(self, username: str, password: str) -> None:
        """Validate a username and password."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        await self.hass.async_add_executor_job(
            self.data.validate_login, username, password
        )

    async def async_get_or_create_credentials(
        self, flow_result: Dict[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        norm_username = self.data.normalize_username
        username = norm_username(flow_result["username"])

        for credential in await self.async_credentials():
            if norm_username(credential.data["username"]) == username:
                return credential

        # Create new credentials.
        return self.async_create_credentials({"username": username})

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Get extra info for this credential."""
        return UserMeta(name=credentials.data["username"], is_active=True)

    async def async_will_remove_credentials(self, credentials: Credentials) -> None:
        """When credentials get removed, also remove the auth."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        try:
            self.data.async_remove_auth(credentials.data["username"])
            await self.data.async_save()
        except InvalidUser:
            # Can happen if somehow we didn't clean up a credential
            pass


class WebAuthnFlow(LoginFlow):
    """Handler for the login flow."""

    async def async_step_init(
        self, user_input: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Handle the step of the form."""
        errors = {}

        if user_input is not None:
            try:
                await cast(
                    WebAuthnAuthProvider, self._auth_provider
                ).async_validate_login(user_input["username"], user_input["password"])
            except InvalidAuth:
                errors["base"] = "invalid_auth"

            if not errors:
                user_input.pop("password")
                return await self.async_finish(user_input)

        schema: Dict[str, type] = OrderedDict()
        schema["username"] = str

        return self.async_show_form(
            step_id="init", data_schema=vol.Schema(schema), errors=errors
        )
