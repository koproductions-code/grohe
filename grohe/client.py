import logging
from typing import Dict, Any

import httpx
from datetime import datetime, timedelta

from .tokens import get_refresh_tokens, get_tokens_from_credentials


class GroheClient:
    def __init__(
        self, email: str, password: str, httpx_client: httpx.AsyncClient = None
    ):
        self.__email: str = email
        self.__password: str = password
        self.__access_token: str | None = None
        self.__refresh_token: str | None = None
        self.__access_token_expiring_date: datetime | None = None
        self.__httpx_client = httpx_client or httpx.AsyncClient()

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
                self.__email, self.__password, self.__httpx_client
            )
            self.__access_token = tokens["access_token"]
            self.__access_token_expiring_date = datetime.now() + timedelta(
                seconds=tokens["access_token_expires_in"] - 60
            )
            self.__refresh_token = tokens["refresh_token"]
        except Exception as e:
            logging.error(f"Could not get initial tokens: {e}")
            raise e

    async def __refresh_tokens(self):
        """
        Refreshes the access and refresh tokens.

        This method asynchronously fetches new access and refresh tokens using the current refresh token.
        It updates the instance's access token, refresh token, and the access token's expiring date.

        Raises:
            Exception: If the token refresh process fails.

        Returns:
            None
        """
        tokens = await get_refresh_tokens(self.__refresh_token, self.__httpx_client)
        self.__access_token = tokens["access_token"]
        self.__refresh_token = tokens["refresh_token"]
        self.__access_token_expiring_date = datetime.now() + timedelta(
            seconds=tokens["access_token_expires_in"] - 60
        )

    async def __get_access_token(self) -> str:
        """
        Retrieves the current access token. If the access token has expired,
        it refreshes the tokens before returning the access token.

        Returns:
            str: The current access token.
        """
        if datetime.now() > self.__access_token_expiring_date:
            await self.__refresh_tokens()
        return self.__access_token


    async def __get(self, url: str) -> Dict[str, Any] | None:
        """
        Retrieve data from the specified URL using a GET request.

        :param url: The URL to retrieve data from.
        :type url: str
        :return: A dictionary containing the retrieved data.
        :rtype: Dict[str, Any]
        """
        access_token = await self.__get_access_token()
        response = await self.__httpx_client.get(url=url, headers={
            'Authorization': f'Bearer {access_token}'
        })

        if response.status_code in (200, 201):
            return await response.json()
        else:
            logging.warning(f'URL {url} returned status code {response.status_code} for GET request')
            return None

    async def __post(self, url: str, data: Dict[str, Any] | None) -> Dict[str, Any]:
        """
        Send a POST request to the specified URL with the given data.

        :param url: The URL to send the request to.
        :type url: str
        :param data: The data to include in the request body.
        :type data: Dict[str, Any]
        :return: A dictionary representing the response JSON.
        :rtype: Dict[str, Any]
        """
        access_token = await self.__get_access_token()
        response = await self.__httpx_client.post(url=url, json=data, headers={
            'Authorization': f'Bearer {access_token}'
        })

        if response.status_code == 201:
            return await response.json()

    async def __put(self, url: str, data: Dict[str, Any] | None) -> Dict[str, Any] | None:
        """
        Send a PUT request to the specified URL with the given data.

        :param url: The URL to send the request to.
        :type url: str
        :param data: The data to include in the request body.
        :type data: Dict[str, Any]
        :return: A dictionary representing the response JSON.
        :rtype: Dict[str, Any]
        """
        access_token = await self.__get_access_token()
        response = await self.__httpx_client.put(url=url, json=data, headers={
            'Authorization': f'Bearer {access_token}'
        })

        if response.status_code == 201:
            return await response.json()
        elif response.status_code == 200:
            return None
        elif response.status_code == 202:
            return None
        else:
            logging.warning(f'URL {url} returned status code {response.status_code} for PUT request')

    async def __delete(self, url: str) -> Dict[str, Any] | None:
        """
        Send a DELETE request to the specified URL with the given data.

        :param url: The URL to send the request to.
        :type url: str
        :return: A dictionary representing the response JSON.
        :rtype: Dict[str, Any]
        """
        access_token = await self.__get_access_token()
        response = await self.__httpx_client.delete(url=url, headers={
            'Authorization': f'Bearer {access_token}'
        })

        if response.status_code == 201:
            return await response.json()
        elif response.status_code == 200:
            return None
        elif response.status_code == 202:
            return None
        else:
            logging.warning(f'URL {url} returned status code {response.status_code} for PUT request')