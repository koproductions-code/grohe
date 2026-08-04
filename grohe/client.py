import logging
from typing import Dict, Any, Optional

import httpx
from datetime import datetime, timedelta

import jwt

from .dto.grohe_dto import GroheTokensDTO, GrohePressureMeasurementStart
from .enum.grohe_enum import GroheTypes, GroheGroupBy
from .exceptions import (
    GroheForbiddenError,
    GroheNetworkError,
    GroheRateLimitError,
    GroheUnauthorizedError,
)
from .tokens import GroheTokens


class GroheClient:
    def __init__(
        self, email: str, password: str, httpx_client: httpx.AsyncClient = None, access_token_refresh_before_expire: int = 60
    ):
        self.__base_url: str = 'https://idp2-apigw.cloud.grohe.com'
        self.__api_url: str = self.__base_url + '/v3/iot'

        self.__email: str = email
        self.__password: str = password
        self.__access_token: str | None = None
        self.__refresh_token: str | None = None
        self.__tokens: GroheTokensDTO | None = None
        self.__access_token_expiring_date: datetime | None = None
        self.__user_id: str | None = None
        self.__access_token_refresh_before_expire: int = access_token_refresh_before_expire
        self.__httpx_client = httpx_client or httpx.AsyncClient()

        self.__token_handler = GroheTokens(self.__httpx_client, self.__api_url)

    @property
    def access_token(self):
        return self.__access_token

    @property
    def user_id(self):
        return self.__user_id

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
        tokens = await self.__token_handler.get_refresh_tokens(self.__refresh_token)
        self.__set_tokens(tokens)


    def __set_tokens(self, tokens: GroheTokensDTO):
        self.__tokens = tokens

        self.__access_token = tokens.access_token
        self.__refresh_token = tokens.refresh_token

        self.__access_token_expiring_date = datetime.now() + timedelta(
            seconds=tokens.expires_in - self.__access_token_refresh_before_expire
        )

        access_token_data = jwt.decode(tokens.access_token, options={'verify_signature': False})
        self.__user_id = access_token_data['sub']

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


    @staticmethod
    def __safe_json(response: httpx.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            return None

    @classmethod
    def __extract_error_message(cls, response: httpx.Response, default: str) -> str:
        body = cls.__safe_json(response)
        if isinstance(body, dict):
            return body.get('errorMessage') or body.get('Message') or default
        return default

    @classmethod
    def __check_response(cls, response: httpx.Response, url: str) -> None:
        """
        Raise a typed error for auth-related response codes so callers can react
        (e.g. trigger re-authentication vs. just backing off). Other non-success
        codes are left to each caller to log/handle as before.
        """
        if response.status_code == 401:
            raise GroheUnauthorizedError(
                cls.__extract_error_message(response, f'Unauthorized (401) for {url}')
            )

        if response.status_code == 403:
            body = cls.__safe_json(response)
            # Grohe returns 403 for two very different reasons, distinguished only by
            # the response body shape:
            # - {"errorCode": 403, "errorMessage": "..."} -> the token itself is invalid
            # - {"Message": "...explicit deny..."} -> valid token, but this request/
            #   endpoint is denied (e.g. rate limiting)
            if isinstance(body, dict) and body.get('errorCode') == 403:
                raise GroheUnauthorizedError(
                    body.get('errorMessage', f'Forbidden (403) for {url}: invalid token')
                )
            raise GroheForbiddenError(
                cls.__extract_error_message(response, f'Forbidden (403) for {url}')
            )

        if response.status_code == 429:
            retry_after = response.headers.get('Retry-After')
            message = f'Rate limited (429) for {url}'
            if retry_after:
                message += f' - retry after {retry_after}s'
            raise GroheRateLimitError(cls.__extract_error_message(response, message))

    async def __get(
        self,
        url: str,
        params: Optional[dict[str, any]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any] | None:
        """
        Retrieve data from the specified URL using a GET request.

        :param url: The URL to retrieve data from.
        :type url: str
        :param timeout: Optional per-request timeout (seconds) overriding the client's
            default - useful for endpoints that are known to occasionally be slow.
        :type timeout: Optional[float]
        :return: A dictionary containing the retrieved data.
        :rtype: Dict[str, Any]
        """
        access_token = await self.__get_access_token()
        kwargs: Dict[str, Any] = {'headers': {'Authorization': f'Bearer {access_token}'}}
        if params:
            kwargs['params'] = params
        if timeout is not None:
            kwargs['timeout'] = timeout

        try:
            response = await self.__httpx_client.get(url=url, **kwargs)
        except httpx.HTTPError as err:
            raise GroheNetworkError(f'GET {url} failed: {err}') from err

        self.__check_response(response, url)

        if response.status_code in (200, 201):
            return response.json()
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
        try:
            response = await self.__httpx_client.post(url=url, json=data, headers={
                'Authorization': f'Bearer {access_token}'
            })
        except httpx.HTTPError as err:
            raise GroheNetworkError(f'POST {url} failed: {err}') from err

        self.__check_response(response, url)

        if response.status_code == 201:
            return response.json()

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
        try:
            response = await self.__httpx_client.put(url=url, json=data, headers={
                'Authorization': f'Bearer {access_token}'
            })
        except httpx.HTTPError as err:
            raise GroheNetworkError(f'PUT {url} failed: {err}') from err

        self.__check_response(response, url)

        if response.status_code in (200, 201, 202):
            # Some endpoints (e.g. appliance config) return the full updated resource in the
            # body even on 200, others reply with an empty body - only parse if there is one.
            if response.content:
                return response.json()
            return None
        else:
            logging.warning(f'URL {url} returned status code {response.status_code} for PUT request')
            return None

    async def __delete(self, url: str) -> Dict[str, Any] | None:
        """
        Send a DELETE request to the specified URL with the given data.

        :param url: The URL to send the request to.
        :type url: str
        :return: A dictionary representing the response JSON.
        :rtype: Dict[str, Any]
        """
        access_token = await self.__get_access_token()
        try:
            response = await self.__httpx_client.delete(url=url, headers={
                'Authorization': f'Bearer {access_token}'
            })
        except httpx.HTTPError as err:
            raise GroheNetworkError(f'DELETE {url} failed: {err}') from err

        self.__check_response(response, url)

        if response.status_code == 201:
            return response.json()
        elif response.status_code == 200:
            return None
        elif response.status_code == 202:
            return None
        else:
            logging.warning(f'URL {url} returned status code {response.status_code} for PUT request')


    def get_tokens(self) -> GroheTokensDTO:
            return self.__tokens

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
            tokens = await self.__token_handler.get_tokens_from_credentials(
                self.__email, self.__password
            )
            self.__set_tokens(tokens)

        except Exception as e:
            logging.error(f"Could not get initial tokens: {e}")
            raise e

    async def get_dashboard(self) -> Dict[str, any]:
        """
        Get the dashboard information.
        These dashboard information include most of the data which can also be queried by the appliance itself

        :return: The locations information obtained from the dashboard.
        :rtype: Dict[str, any]
        """
        logging.debug('Get dashboard information')
        url = f'{self.__api_url}/dashboard'
        return await self.__get(url)

    async def get_appliance_info(self, location_id: str, room_id: str, appliance_id: str) -> Dict[str, any]:
        """
        Get information about an appliance.

        :param location_id: ID of the location containing the appliance.
        :type location_id: str
        :param room_id: ID of the room containing the appliance.
        :type room_id: str
        :param appliance_id: ID of the appliance to get details for.
        :type appliance_id: str
        :return: The information of the appliance.
        :rtype: Dict[str, any]
        """
        logging.debug('Get appliance information for appliance %s', appliance_id)
        url = f'{self.__api_url}/locations/{location_id}/rooms/{room_id}/appliances/{appliance_id}'
        data = await self.__get(url)

        # The API wraps the single appliance in a list, even though the URL is already
        # scoped to one specific appliance_id.
        if isinstance(data, list):
            return data[0] if data else None

        return data

    async def get_appliance_config(self, location_id: str, room_id: str,
                                   appliance_id: str) -> Dict[str, Any] | None:
        """
        Get the current configuration of an appliance, as returned by the API.

        The shape of this dict is appliance-type specific and not modeled here on purpose -
        e.g. Sense Guard exposes thresholds/monitoring flags/sprinkler schedule, other
        appliance types may expose a different (or no) set of fields.

        :param location_id: ID of the location containing the appliance.
        :type location_id: str
        :param room_id: ID of the room containing the appliance.
        :type room_id: str
        :param appliance_id: ID of the appliance to get the config for.
        :type appliance_id: str
        :return: The raw appliance configuration, or None if it could not be retrieved.
        :rtype: Dict[str, Any] | None
        """
        logging.debug('Get appliance config for appliance %s', appliance_id)
        info = await self.get_appliance_info(location_id, room_id, appliance_id)

        if info is None:
            return None

        return info.get('config')

    async def set_appliance_config(self, location_id: str, room_id: str, appliance_id: str,
                                   config: Dict[str, Any]) -> Dict[str, Any] | None:
        """
        Update the configuration of an appliance. `config` is sent as-is, so it can be a full
        config dict or just the subset of keys that should change - e.g.
        {"sprinkler_mode_active_monday": False} updates only that flag.

        :param location_id: ID of the location containing the appliance.
        :type location_id: str
        :param room_id: ID of the room containing the appliance.
        :type room_id: str
        :param appliance_id: ID of the appliance to update the config for.
        :type appliance_id: str
        :param config: The (partial or full) configuration to apply.
        :type config: Dict[str, Any]
        :return: The full, updated appliance resource as returned by the API, or None if the
                 response had no body.
        :rtype: Dict[str, Any] | None
        """
        logging.debug('Set appliance config for appliance %s', appliance_id)
        url = f'{self.__api_url}/locations/{location_id}/rooms/{room_id}/appliances/{appliance_id}'
        return await self.__put(url, {'config': config})


    async def get_appliance_details(self, location_id: str, room_id: str, appliance_id: str) -> Dict[str, any]:
        """
        Get information about an appliance without parsing it to a struct.

        :param location_id: ID of the location containing the appliance.
        :type location_id: str
        :param room_id: ID of the room containing the appliance.
        :type room_id: str
        :param appliance_id: ID of the appliance to get details for.
        :type appliance_id: str
        :return: The information of the appliance.
        :rtype: Dict[str, any]
        """
        logging.debug('Get appliance details for appliance (type insensitive) %s', appliance_id)

        dashboard_data = await self.get_dashboard()
        
        # Extract specific appliance data from dashboard
        api_data = None
        for location in dashboard_data.get('locations', []):
            if location['id'] == location_id:
                for room in location.get('rooms', []):
                    if room['id'] == room_id:
                        for appliance in room.get('appliances', []):
                            if appliance['appliance_id'] == appliance_id:
                                api_data = appliance
                                break
                        if api_data:
                            break
                if api_data:
                    break
        
        if api_data is None:
            logging.error(f'Appliance with ID {appliance_id} not found in dashboard data')
            return {}
        
        return api_data


    async def get_appliance_status(self, location_id: str, room_id: str, appliance_id: str) -> Dict[str, any]:
        url = f'{self.__api_url}/locations/{location_id}/rooms/{room_id}/appliances/{appliance_id}/status'
        return await self.__get(url)

    async def get_appliance_command(self, location_id: str, room_id: str, appliance_id: str) -> Dict[str, any]:
        """
        Get possible commands for an appliance.

        :param location_id: ID of the location containing the appliance.
        :type location_id: str
        :param room_id: ID of the room containing the appliance.
        :type room_id: str
        :param appliance_id: ID of the appliance to get details for.
        :type appliance_id: str
        :return: The command for the specified appliance.
        :rtype: Dict[str, any]
        """
        logging.debug('Get appliance command for appliance %s', appliance_id)
        url = f'{self.__api_url}/locations/{location_id}/rooms/{room_id}/appliances/{appliance_id}/command'
        return await self.__get(url)


    async def get_appliance_notifications(self, location_id: str, room_id: str,
                                          appliance_id: str, limit: Optional[int] = None) -> Dict[str, any]:

        url = f'{self.__api_url}/locations/{location_id}/rooms/{room_id}/appliances/{appliance_id}/notifications'

        params = dict()

        if limit is not None:
            params.update({'pageSize': limit})

        data = await self.__get(url, params)
        return data

    async def get_appliance_data(self, location_id: str, room_id: str, appliance_id: str,
                                 from_date: Optional[datetime] = None, to_date: Optional[datetime] = None,
                                 group_by: Optional[GroheGroupBy] = None,
                                 date_as_full_day: Optional[bool] = None,
                                 timeout: Optional[float] = None) -> Dict[str, any]:

        url = f'{self.__api_url}/locations/{location_id}/rooms/{room_id}/appliances/{appliance_id}/data/aggregated'
        params = dict()

        if from_date is not None:
            if date_as_full_day:
                params.update({'from': from_date.date()})
            else:
                params.update({'from': from_date.strftime('%Y-%m-%dT%H:%M:%S%z')})
        if to_date is not None:
            if date_as_full_day:
                params.update({'to': to_date.date()})
            else:
                params.update({'to': to_date.strftime('%Y-%m-%dT%H:%M:%S%z')})
        if group_by is not None:
            params.update({'groupBy': group_by.value})

        return await self.__get(url, params, timeout=timeout)


    async def set_appliance_command(self, location_id: str, room_id: str, appliance_id: str, device_type: GroheTypes, data: Dict[str, any]) -> Dict[str, any]:
        url = f'{self.__api_url}/locations/{location_id}/rooms/{room_id}/appliances/{appliance_id}/command'
        data['type'] = device_type.value
        return await self.__post(url, data)


    async def start_pressure_measurement(self, location_id: str, room_id: str,
                                         appliance_id: str) -> GrohePressureMeasurementStart | None:
        """
        This method sets the command for a specific appliance. It takes the location ID, room ID, appliance ID,
        command, and value as parameters.

        :param location_id: ID of the location containing the appliance.
        :type location_id: str
        :param room_id: ID of the room containing the appliance.
        :type room_id: str
        :param appliance_id: ID of the appliance to get details for.
        :type appliance_id: str
        :return: None
        """
        logging.debug('Start pressure measurement for appliance %s',appliance_id)
        url = f'{self.__api_url}/locations/{location_id}/rooms/{room_id}/appliances/{appliance_id}/pressuremeasurement'

        response = await self.__post(url, None)

        if response is not None:
            return GrohePressureMeasurementStart.from_dict(response)
        else:
            return None

    async def get_appliance_pressure_measurement(self, location_id: str, room_id: str,
                                                     appliance_id: str) -> Dict[str, any]:
        url = f'{self.__api_url}/locations/{location_id}/rooms/{room_id}/appliances/{appliance_id}/pressuremeasurement'
        data = await self.__get(url)
        return data

    async def set_snooze(self, location_id: str, room_id: str,
                            appliance_id: str, duration_in_min: int) -> Dict[str, any]:
        url = f'{self.__api_url}/locations/{location_id}/rooms/{room_id}/appliances/{appliance_id}/snooze'
        data = await self.__put(url, {'snooze_duration': duration_in_min})
        return data

    async def disable_snooze(self, location_id: str, room_id: str,
                            appliance_id: str) -> None:
        url = f'{self.__api_url}/locations/{location_id}/rooms/{room_id}/appliances/{appliance_id}/snooze'
        data = await self.__delete(url)
        return data

    async def get_profile_notifications(self, page_size: int = 50) -> Dict[str, any]:
        url = f'{self.__api_url}/profile/notifications?pageSize={page_size}'
        data = await self.__get(url)
        return data


    async def update_profile_notification_state(self, notification_id: str, state: bool) -> None:
        """
            Get profile notifications.

            :param notification_id: The unique ID of the notification to update.
            :param state: Sets the state of the notification
            :return: None.
        """
        logging.debug('Set state of notification %s to %s', notification_id, state)
        url = f'{self.__api_url}/profile/notifications/{notification_id}'
        data = {'is_read': state}
        ret_val = await self.__put(url, data)
        logging.debug(f'Notification {notification_id} updated. Return value: {ret_val}')

        return None
