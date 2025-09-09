import logging
from typing import Dict, Any, Optional

import httpx
from datetime import datetime, timedelta

import jwt

from .dto.grohe_dto import GroheTokensDTO, GrohePressureMeasurementStart
from .enum.grohe_enum import GroheTypes, GroheGroupBy
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


    async def __get(self, url: str, params: Optional[dict[str, any]] = None) -> Dict[str, Any] | None:
        """
        Retrieve data from the specified URL using a GET request.

        :param url: The URL to retrieve data from.
        :type url: str
        :return: A dictionary containing the retrieved data.
        :rtype: Dict[str, Any]
        """
        access_token = await self.__get_access_token()
        if params:
            response = await self.__httpx_client.get(url=url, headers={
                'Authorization': f'Bearer {access_token}'
            }, params=params)
        else:
            response = await self.__httpx_client.get(url=url, headers={
                'Authorization': f'Bearer {access_token}'
            })

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
        response = await self.__httpx_client.post(url=url, json=data, headers={
            'Authorization': f'Bearer {access_token}'
        })

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
        response = await self.__httpx_client.put(url=url, json=data, headers={
            'Authorization': f'Bearer {access_token}'
        })

        if response.status_code == 201:
            return response.json()
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
        return await self.__get(url)


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
                                 date_as_full_day: Optional[bool] = None) -> Dict[str, any]:

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

        return await self.__get(url, params)


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
