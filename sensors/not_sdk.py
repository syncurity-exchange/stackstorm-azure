from st2reactor.sensor.base import PollingSensor

import time
import requests


class NotSDKAlerts(PollingSensor):
    def __init__(self, sensor_service, config=None, poll_interval=None, ):
        super(NotSDKAlerts, self).__init__(sensor_service=sensor_service,
                                           config=config,
                                           poll_interval=poll_interval)

        self.logger = sensor_service.get_logger(name='NotSDKAlerts')

        self.trigger_ref = "azure.not_sdk"

        token = self.config['token']
        self.headers = {
            'Authorization': 'Bearer ' + token
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

        alerts = requests.get('https://management.azure.com/subscriptions/' +
                              self.subscription_id +
                              '/providers/Microsoft.Security/alerts?api-version=2019-01-01')

        self.logger.info(alerts)

        for alert in alerts:

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
