import httpx
import urllib.parse
from bs4 import BeautifulSoup

from grohe.dto.grohe_dto import GroheTokensDTO


class GroheTokens:
    def __init__(self, httpx_client: httpx.AsyncClient, api_url: str):
        self.__client = httpx_client
        self.__api_url = api_url


    async def get_tokens_from_credentials(self, grohe_email: str, grohe_password: str) -> GroheTokensDTO:
        """
        Get the initial access and refresh tokens from the given Grohe credentials.
        Args:
            grohe_email: The Grohe email.
            grohe_password: The Grohe password.

        Returns: A dict with the tokens.
        """
        response = await self.__client.get(f'{self.__api_url}/oidc/login', follow_redirects=True)
        response.raise_for_status()
        html = response.text

        soup = BeautifulSoup(html, 'html.parser')
        form = soup.find('form')
        if not form or 'action' not in form.attrs:
            raise Exception('Login form target URL not found')

        action_url = urllib.parse.urljoin(f'{self.__api_url}/oidc/login', form['action'])

        payload = {
            'username': grohe_email,
            'password': grohe_password,
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': f'{self.__api_url}/oidc/login',
        }

        try:
            response = await self.__client.post(
                action_url, data=payload, headers=headers, follow_redirects=False
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 302:
                location = exc.response.headers.get('Location')
                if not location:
                    raise Exception('No redirect location found after login')

                tokens_url = location.replace('ondus://', 'https://')

                response = await self.__client.get(tokens_url)
                response.raise_for_status()
                json_data = response.json()

                tokens = GroheTokensDTO.from_dict(json_data)
                return tokens
            else:
                raise

        raise Exception(
            'Invalid username/password or unexpected response from Grohe service'
        )

    async def get_refresh_tokens(self, refresh_token: str) -> GroheTokensDTO:
        """
        Refresh the access and refresh tokens.
        Args:
            refresh_token: The refresh token.

        Returns: A dict with the new tokens.
        """
        data = {'refresh_token': refresh_token, 'grant_type': 'refresh_token'}
        response = await self.__client.post(f'{self.__api_url}/oidc/refresh', json=data)
        response.raise_for_status()
        json_data = response.json()

        tokens = GroheTokensDTO.from_dict(json_data)
        return tokens
