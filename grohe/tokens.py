import httpx
import urllib.parse
from bs4 import BeautifulSoup

from grohe.dto.grohe_dto import GroheTokensDTO
from grohe.exceptions import GroheError, GroheNetworkError, GroheUnauthorizedError


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
        try:
            response = await self.__client.get(f'{self.__api_url}/oidc/login', follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as err:
            raise GroheNetworkError(f'Could not load Grohe login page: {err}') from err
        html = response.text

        soup = BeautifulSoup(html, 'html.parser')
        form = soup.find('form')
        if not form or 'action' not in form.attrs:
            raise GroheError('Login form target URL not found')

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
                    raise GroheError('No redirect location found after login')

                tokens_url = location.replace('ondus://', 'https://')

                try:
                    response = await self.__client.get(tokens_url)
                    response.raise_for_status()
                except httpx.HTTPError as err:
                    raise GroheNetworkError(f'Could not fetch tokens after login: {err}') from err

                json_data = response.json()
                tokens = GroheTokensDTO.from_dict(json_data)
                return tokens
            elif exc.response.status_code in (401, 403):
                raise GroheUnauthorizedError('Invalid Grohe username or password') from exc
            else:
                raise GroheNetworkError(f'Unexpected response during login: {exc}') from exc
        except httpx.HTTPError as err:
            raise GroheNetworkError(f'Could not log in to Grohe: {err}') from err

        raise GroheUnauthorizedError(
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
        try:
            response = await self.__client.post(f'{self.__api_url}/oidc/refresh', json=data)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                raise GroheUnauthorizedError('Grohe refresh token is no longer valid') from exc
            raise GroheNetworkError(f'Could not refresh Grohe tokens: {exc}') from exc
        except httpx.HTTPError as err:
            raise GroheNetworkError(f'Could not refresh Grohe tokens: {err}') from err

        json_data = response.json()
        tokens = GroheTokensDTO.from_dict(json_data)
        return tokens
