# Copyright (c) 2013 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from stackinabox.stack import StackInABox
import stackinabox.util.requests_mock

from eom import metrics
from tests import util
from tests.util.httpstatsd import HttpStatsdService
from tests.util.statsd_http_client import HttpStatsdClient


class TestMetrics(util.TestCase):

    def setUp(self):
        super(TestMetrics, self).setUp()
        self.service = HttpStatsdService()
        StackInABox.register_service(self.service)
        self.statsd_client = HttpStatsdClient('http://localhost/statsd/')

    def tearDown(self):
        super(TestMetrics, self).tearDown()
        StackInABox.reset_services()

    def test_basic(self):
        with stackinabox.util.requests_mock.activate():
            stackinabox.util.requests_mock.requests_mock_registration(
                'localhost')
            with mock.patch('statsd.StatsClient') as mock_statsd_client:
                mock_statsd_client.return_value = self.statsd_client

                self.metrics = metrics.Metrics(util.app, util.CONF)

    def test_delete(self):
        with stackinabox.util.requests_mock.activate():
            stackinabox.util.requests_mock.requests_mock_registration(
                'localhost')
            with mock.patch('statsd.StatsClient') as mock_statsd_client:
                mock_statsd_client.return_value = self.statsd_client

                self.metrics = metrics.Metrics(util.app, util.CONF)

                my_env = self.create_env('/', method='DELETE')

                self.assertIn('REQUEST_METHOD', my_env)
                self.assertIn('PATH_INFO', my_env)
                self.metrics(my_env, self.start_response)

    def test_get(self):
        with stackinabox.util.requests_mock.activate():
            stackinabox.util.requests_mock.requests_mock_registration(
                'localhost')
            with mock.patch('statsd.StatsClient') as mock_statsd_client:
                mock_statsd_client.return_value = self.statsd_client

                self.metrics = metrics.Metrics(util.app, util.CONF)

                my_env = self.create_env('/', method='GET')

                self.assertIn('REQUEST_METHOD', my_env)
                self.assertIn('PATH_INFO', my_env)
                self.metrics(my_env, self.start_response)

    def test_head(self):
        with stackinabox.util.requests_mock.activate():
            stackinabox.util.requests_mock.requests_mock_registration(
                'localhost')
            with mock.patch('statsd.StatsClient') as mock_statsd_client:
                mock_statsd_client.return_value = self.statsd_client

                self.metrics = metrics.Metrics(util.app, util.CONF)

                my_env = self.create_env('/', method='HEAD')

                self.assertIn('REQUEST_METHOD', my_env)
                self.assertIn('PATH_INFO', my_env)
                self.metrics(my_env, self.start_response)

    def test_patch(self):
        with stackinabox.util.requests_mock.activate():
            stackinabox.util.requests_mock.requests_mock_registration(
                'localhost')
            with mock.patch('statsd.StatsClient') as mock_statsd_client:
                mock_statsd_client.return_value = self.statsd_client

                self.metrics = metrics.Metrics(util.app, util.CONF)

                my_env = self.create_env('/', method='PATCH')

                self.assertIn('REQUEST_METHOD', my_env)
                self.assertIn('PATH_INFO', my_env)
                self.metrics(my_env, self.start_response)

    def test_post(self):
        with stackinabox.util.requests_mock.activate():
            stackinabox.util.requests_mock.requests_mock_registration(
                'localhost')
            with mock.patch('statsd.StatsClient') as mock_statsd_client:
                mock_statsd_client.return_value = self.statsd_client

                self.metrics = metrics.Metrics(util.app, util.CONF)

                my_env = self.create_env('/', method='POST')

                self.assertIn('REQUEST_METHOD', my_env)
                self.assertIn('PATH_INFO', my_env)
                self.metrics(my_env, self.start_response)

    def test_put(self):
        with stackinabox.util.requests_mock.activate():
            stackinabox.util.requests_mock.requests_mock_registration(
                'localhost')
            with mock.patch('statsd.StatsClient') as mock_statsd_client:
                mock_statsd_client.return_value = self.statsd_client

                self.metrics = metrics.Metrics(util.app, util.CONF)

                my_env = self.create_env('/', method='PUT')

                self.assertIn('REQUEST_METHOD', my_env)
                self.assertIn('PATH_INFO', my_env)
                self.metrics(my_env, self.start_response)

    def test_invalid_method(self):
        with stackinabox.util.requests_mock.activate():
            stackinabox.util.requests_mock.requests_mock_registration(
                'localhost')
            with mock.patch('statsd.StatsClient') as mock_statsd_client:
                mock_statsd_client.return_value = self.statsd_client

                self.metrics = metrics.Metrics(util.app, util.CONF)

                my_env = self.create_env('/', method='INVALID')

                self.assertIn('REQUEST_METHOD', my_env)
                self.assertIn('PATH_INFO', my_env)
                self.metrics(my_env, self.start_response)
