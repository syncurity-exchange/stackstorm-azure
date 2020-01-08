from st2reactor.sensor.base import PollingSensor
from datetime import datetime
import time
import requests
from msgraph_auth import MSAuth


class NotSDKAlerts(PollingSensor):
    def __init__(self, sensor_service, config=None, poll_interval=None, ):
        super(NotSDKAlerts, self).__init__(sensor_service=sensor_service,
                                           config=config,
                                           poll_interval=poll_interval)

        self.logger = sensor_service.get_logger(name='NotSDKAlerts')

        self.trigger_ref = "azure.not_sdk"
        
        resource_manager = config['resource_manager']

        token = MSAuth.client_credentials_authentication(
                    tenant_id=resource_manager['tenant'],
                    client_id=resource_manager['client_id'],
                    client_secret=resource_manager['secret'])
        
        self.headers = {
            'Authorization': 'Bearer ' + str(token)
        }

        self.subscription_id = config['compute']['subscription_id']

    def setup(self):
        pass

    def poll(self):

        # last_timestamp = int(self._get_last_timestamp())
        #
        # current_timestamp = (int(time.time()) - 60) * 1000
        # self.logger.info('Checking for alerts between {0} and {1}'.format(last_timestamp,
        #                                                                   current_timestamp))

        url = 'https://management.azure.com/subscriptions/' + self.subscription_id + \
              '/providers/Microsoft.Security/alerts?api-version=2019-01-01'

        self.logger.info(url)
        self.logger.info(self.headers)

        alerts = requests.get(url, headers=self.headers)

        self.logger.info(alerts)

        for alert in alerts:

            try:
                dt_obj = datetime.strptime(alert['properties']['reportedTimeUtc'],
                                           '%d.%m.%Y %H:%M:%S')
                millisec = dt_obj.timestamp() * 1000
                alert['properties']['timestamp'] = millisec
            except:
                self.logger.info('Could not convert timestamp')

            self.sensor_service.dispatch(trigger=self.trigger_ref,
                                         payload=alert)

        # # todo
        # # if alert_time:
        # #     self._set_last_timestamp(alert_time)
        # else:
        #     self._set_last_timestamp(current_timestamp)

    def _get_last_timestamp(self):
        stored = self.sensor_service.get_value('last_timestamp')

        if stored:
            return stored

        self.logger.info('No stored timestamp found. Using one hour ago.')

        return (int(time.time()) - 3600) * 1000

    def _set_last_timestamp(self, last_timestamp):

        self.logger.info('Setting timestamp for to ' + str(last_timestamp))

        if hasattr(self.sensor_service, 'set_value'):
            self.sensor_service.set_value(name='last_timestamp', value=last_timestamp)

    def cleanup(self):
        pass

    def add_trigger(self, trigger):
        pass

    def update_trigger(self, trigger):
        pass

    def remove_trigger(self, trigger):
        pass
