import logging
import asyncio
import httpx
from datetime import datetime, timedelta

from .tokens import get_refresh_tokens, get_tokens_from_credentials


class GroheClient:
    def __init__(
        self, email: str, password: str, httpx_client: httpx.AsyncClient = None
    ):
        self.email = email
        self.password = password
        self.access_token = None
        self.refresh_token = None
        self.access_token_expiring_date = None
        self.httpx_client = httpx_client or httpx.AsyncClient()

    async def login(self):
        """
        Asynchronously logs in the user by obtaining access and refresh tokens using provided credentials.

        This method attempts to retrieve tokens using the user's email and password. If successful, it sets the
        access token, its expiration date, and the refresh token for the user. If it fails, it logs an error
        message and raises the exception.

        Raises:
            Exception: If there is an error obtaining the tokens.

        Returns:
            None
        """
        try:
            tokens = await get_tokens_from_credentials(
                self.email, self.password, self.httpx_client
            )
            self.access_token = tokens["access_token"]
            self.access_token_expiring_date = datetime.now() + timedelta(
                seconds=tokens["access_token_expires_in"] - 60
            )
            self.refresh_token = tokens["refresh_token"]
        except Exception as e:
            logging.error(f"Could not get initial tokens: {e}")
            raise e

    async def refresh_tokens(self):
        """
        Refreshes the access and refresh tokens.

        This method asynchronously fetches new access and refresh tokens using the current refresh token.
        It updates the instance's access token, refresh token, and the access token's expiring date.

        Raises:
            Exception: If the token refresh process fails.

        Returns:
            None
        """
        tokens = await get_refresh_tokens(self.refresh_token, self.httpx_client)
        self.access_token = tokens["access_token"]
        self.refresh_token = tokens["refresh_token"]
        self.access_token_expiring_date = datetime.now() + timedelta(
            seconds=tokens["access_token_expires_in"] - 60
        )

    async def get_access_token(self) -> str:
        """
        Retrieves the current access token. If the access token has expired,
        it refreshes the tokens before returning the access token.

        Returns:
            str: The current access token.
        """
        if datetime.now() > self.access_token_expiring_date:
            await self.refresh_tokens()
        return self.access_token

    """
    Hier hatte ich bei meinem Package die Funktionen für die API-Requests 
    (https://github.com/koproductions-code/groheblue/blob/master/groheblue/client.py).
    """