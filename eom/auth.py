# Copyright (c) 2014 Rackspace, Inc.
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

import base64
import datetime
import functools

from keystoneclient import access
from keystoneclient import exceptions
from keystoneclient.v2_0 import client as keystone_v2_client
import msgpack
from oslo_config import cfg
import redis
from redis import connection
import simplejson as json
import six

from eom.utils import log as logging

_CONF = cfg.CONF
LOG = logging.getLogger(__name__)

MAX_CACHE_LIFE_DEFAULT = ((datetime.datetime.max -
                           datetime.datetime.utcnow()).total_seconds() - 30)

AUTH_GROUP_NAME = 'eom:auth'
AUTH_OPTIONS = [
    cfg.StrOpt(
        'auth_url',
        help='Identity url to authenticate tokens.'
    ),
    cfg.IntOpt(
        'blacklist_ttl',
        help='Time to live in seconds for tokens marked as unauthorized.'
    ),
    cfg.IntOpt(
        'max_cache_life',
        help='Time to live in seconds for valid tokens.',
        # default value is the maximum number of seconds
        # that the datetime module can manage, with a buffer
        # of 30 seconds so we won't brush up against the end
        # or overflow when adding to utcnow() later on
        default=MAX_CACHE_LIFE_DEFAULT
    )
]

REDIS_GROUP_NAME = 'eom:auth_redis'
REDIS_OPTIONS = [
    cfg.StrOpt('host'),
    cfg.StrOpt('port'),
    cfg.IntOpt('redis_db', default=0),
    cfg.StrOpt('password', default=None),
    cfg.BoolOpt('ssl_enable', default=False),
    cfg.StrOpt('ssl_keyfile', default=None),
    cfg.StrOpt('ssl_certfile', default=None),
    cfg.StrOpt('ssl_cert_reqs', default=None),
    cfg.StrOpt('ssl_ca_certs', default=None),
]


class InvalidKeystoneClient(Exception):
    pass


class InvalidAccessInformation(Exception):
    pass


class UnknownAuthenticationDataVersion(Exception):
    pass


class Auth(object):
    """Authentication middleware that uses OpenStack Keystone APIs."""
    def __init_(self, app, conf, *args, **kwargs):
        self.app = app
        self._redis_client = None

        conf.register_opts(AUTH_OPTIONS, group=AUTH_GROUP_NAME)
        conf.register_opts(REDIS_OPTIONS, group=REDIS_GROUP_NAME)

        self._auth_conf = conf[AUTH_GROUP_NAME]
        self._redis_conf = conf[REDIS_GROUP_NAME]

        self.packer = msgpack.Packer(encoding='utf-8', use_bin_type=True)
        self.unpacker = functools.partial(msgpack.unpackb, encoding='utf-8')

    def configure(self, config):
        global _CONF
        global LOG

        _CONF = config
        _CONF.register_opts(AUTH_OPTIONS, group=AUTH_GROUP_NAME)
        _CONF.register_opts(REDIS_OPTIONS, group=REDIS_GROUP_NAME)

        logging.register(_CONF, AUTH_GROUP_NAME)
        logging.setup(_CONF, AUTH_GROUP_NAME)
        LOG = logging.getLogger(__name__)

    def get_conf(self, redis_config=False):
        global _CONF
        if redis_config:
            return _CONF[REDIS_GROUP_NAME]
        else:
            return _CONF[AUTH_GROUP_NAME]

    @property
    def redis_client(self):
        """Get a Redis Client connection from the pool

        uses the eom:auth_redis settings
        """

        if self._redis_conf['ssl_enable']:
            pool = redis.ConnectionPool(
                host=self._redis_conf['host'],
                port=self._redis_conf['port'],
                db=self._redis_conf['redis_db'],
                password=self._redis_conf['password'],
                ssl_keyfile=self._redis_conf['ssl_keyfile'],
                ssl_certfile=self._redis_conf['ssl_certfile'],
                ssl_cert_reqs=self._redis_conf['ssl_cert_reqs'],
                ssl_ca_certs=self._redis_conf['ssl_ca_certs'],
                connection_class=connection.SSLConnection
            )
        else:
            pool = redis.ConnectionPool(
                host=self._redis_conf['host'],
                port=self._redis_conf['port'],
                db=self._redis_conf['redis_db']
            )
        return redis.Redis(connection_pool=pool)

    @staticmethod
    def _tuple_to_cache_key(t):
        """Convert a tuple to a cache key."""
        key = '(%(s_data)s)'.format(
            {'s_data': ','.join(t)}
        )
        return key

    def _blacklist_token(self, token, expires_in):
        """Stores the token to the blacklist data in the cache

        :param token: auth_token for the user
        :param expires_in: time in milliseconds for blacklisting failed tokens

        :returns: True on success, otherwise False
        """
        try:
            cache_data = self.packer.pack(True)
            cache_key = token

            self.redis_client.set(cache_key, cache_data)
            self.redis_client.pexpire(cache_key, expires_in)
            return True

        except Exception as ex:
            msg = ('Failed to cache the data - Exception: %(s_except)s' % {
                's_except': ex,
            })
            LOG.error(msg)
            return False

    def _is_token_blacklisted(self, token):
        """Determines if the token is in the cached blacklist data

        :param token: auth_token for the user

        :returns: True on success, otherwise False
        """
        cached_data = None
        cached_key = None
        try:
            cached_key = token

            cached_data = self.redis_client.get(cached_key)
        except Exception:
            LOG.debug('Failed to retrieve data to cache for key %(s_key)s' % {
                's_key': cached_key
            })

        if cached_data is None:
            return False
        else:
            return True

    @staticmethod
    def _get_expiration_time(service_catalog_expiration_time, max_cache_life):
        """Determines the cache expiration time

        :param service_catalog_expiration_time: DateTime object containing the
               expiration time from the service catalog
        :param max_cache_life: time in seconds for the maximum time a cache
            entry should remain in the cache of valid data

        :returns: DateTime object with the time that the cache should be
                  expired at. This is the nearest time of either the
                  expiration of the service catalog or the combination of
                  the current time and the max_cache_life parameter
        """
        class UtcTzInfo(datetime.tzinfo):

            def utcoffset(self, dt):
                return datetime.timedelta(0)

            def tzname(self, dt):
                return 'UTC'

            def dst(self, dt):
                return datetime.timedelta(0)

        # calculate the time based on the max_cache_life
        now = datetime.datetime.utcnow()
        max_expire_time = now + datetime.timedelta(seconds=max_cache_life)

        if (
            service_catalog_expiration_time.tzinfo
            is not None
        ):  # pragma: no cover
            max_expire_time = max_expire_time.replace(tzinfo=UtcTzInfo())

        # return the nearest time to now
        return min(service_catalog_expiration_time,
                   max_expire_time)

    def _send_data_to_cache(self, url, access_info, max_cache_life):
        """Stores the authentication data to cache

        :param url: URL used for authentication
        :param access_info: keystoneclient.access.AccessInfo containing
            the auth data
        :param max_cache_life: time in seconds a cache entry should remain in
            the cache of valid data

        :returns: True on success, otherwise False
        """
        try:
            # Convert the storable format
            cache_data = self.packer.pack(access_info)

            tenant = access_info.tenant_id
            token = access_info.auth_token

            # Build the cache key and store the value
            cache_key = self._tuple_to_cache_key((tenant, token, url))
            self.redis_client.set(cache_key, cache_data)

            # Get the cache expiration time
            cache_expiration_time = self._get_expiration_time(
                access_info.expires,
                max_cache_life
            )

            self.redis_client.pexpireat(cache_key, cache_expiration_time)

            return True

        except Exception as ex:
            msg = 'Failed to cache the data - Exception: %(s_except)s' % {
                's_except': ex,
            }
            LOG.error(msg)
            return False

    def _retrieve_data_from_cache(self, url, tenant, token):
        """Retrieve the authentication data from cache

        :param url: URL used for authentication
        :param tenant: tenant id of the user
        :param token: auth_token for the user

        :returns: a keystoneclient.access.AccessInfo on success or None
        """
        cache_key = None
        try:
            # Try to get the data from the cache
            cache_key_tuple = (tenant, token, url)
            cache_key = self._tuple_to_cache_key(cache_key_tuple)
            cached_data = self.redis_client.get(cache_key)
        except Exception:
            LOG.debug('Failed to retrieve data to cache for key %(s_key)s' % {
                's_key': cache_key
            })
            return None

        if cached_data is not None:
            # So 'data' can be used in the exception handler...
            data = None

            try:
                data = self.unpacker(cached_data)
                return access.AccessInfoV2(data)

            except Exception as ex:
                # The cached object didn't match what we expected
                msg = (
                    'Stored Data does not contain any credentials - '
                    'Exception: %(s_except)s; Data: $(s_data)s'
                ).format({
                    's_except': ex,
                    's_data': data
                })
                LOG.error(msg)
                return None
        else:
            LOG.debug('No data in cache for key %(s_key)s' % {
                's_key': cache_key
            })
            # It wasn't cached
            return None

    def _retrieve_data_from_keystone(self, url, tenant, token,
                                     blacklist_ttl, max_cache_life):
        """Retrieve the authentication data from OpenStack Keystone

        :param url: Keystone Identity URL to authenticate against
        :param tenant: tenant id of user data to retrieve
        :param token: auth_token for the tenant_id
        :param blacklist_ttl: time in milliseconds for blacklisting failed
            tokens
        :param max_cache_life: time in seconds for the maximum time a cache
            entry should remain in the cache of valid data

        :returns: keystoneclient.access.AccessInfo on success or None on error
        """
        try:
            keystone = keystone_v2_client.Client(
                tenant_id=tenant,
                token=token,
                auth_url=url
            )

            # Now try to authenticate the user and get the user
            # information using only the data provided.
            # no special administrative tokens required
            access_info = keystone.get_raw_token_from_identity_service(
                auth_url=url, tenant_id=tenant, token=token)

            # cache the data so it is easier to access next time
            self._send_data_to_cache(url, access_info, max_cache_life)

            return access_info

        except (
            exceptions.AuthorizationFailure,
            exceptions.Unauthorized
        ) as ex:
            # Provided data was invalid and authorization failed
            msg = (
                'Failed to authenticate against %(s_url) - %(s_except)s'
            ).format({
                's_url': url,
                's_except': ex
            })
            LOG.debug(msg)

            # Blacklist the token
            self._blacklist_token(token, blacklist_ttl)
            return None

        except Exception as ex:
            # Provided data was invalid or something else went wrong
            msg = (
                'Failed to authenticate against %(s_url) - %(s_except)s'
            ).format({
                's_url': url,
                's_except': ex
            })
            LOG.debug(msg)

            return None

    def _get_access_info(self, url, tenant, token, blacklist_ttl,
                         max_cache_life):
        """Retrieve the access information regarding the specified user

        :param url: Keystone Identity URL to authenticate against
        :param tenant: tenant id of user data to retrieve
        :param token: auth_token for the tenant_id
        :param blacklist_ttl: time in milliseconds for blacklisting failed
            tokens
        :param max_cache_life: time in seconds for the maximum time a cache
            entry should remain in the cache of valid data

        :returns: keystoneclient.access.AccessInfo for the user on success
                  None on error
        """

        # Check cache
        access_info = self._retrieve_data_from_cache(
            url,
            tenant,
            token
        )

        if access_info is not None:
            if access_info.will_expire_soon():
                LOG.info('Token has expired')
                del access_info
                access_info = None

        # Check if we failed to get it from the cache and
        # retrieve from keystone instead
        if access_info is None:
            LOG.debug('Failed to retrieve token from cache. Trying Keystone')
            access_info = self._retrieve_data_from_keystone(
                url,
                tenant,
                token,
                blacklist_ttl,
                max_cache_life
            )
        else:
            LOG.debug('Retrieved token from cache.')

        # Validate we have an access object and
        # Make sure it's not already expired
        if access_info is not None:
            if access_info.will_expire_soon():
                LOG.info('Token has expired')
                del access_info
                access_info = None

        # Return the access data
        return access_info

    def _validate_client(self, url, tenant, token, env,
                         blacklist_ttl, max_cache_life):
        """Update the env with the access information for the user

        :param url: Keystone Identity URL to authenticate against
        :param tenant: tenant id of user data to retrieve
        :param token: auth_token for the tenant_id
        :param env: environment variable dictionary for the client connection
        :param blacklist_ttl: time in milliseconds for blacklisting failed
            tokens
        :param max_cache_life: time in seconds for the maximum time a cache
            entry should remain in the cache of valid data

        :returns: True on success, otherwise False
        """

        def _management_url(*args, **kwargs):
            return url

        def patch_management_url():
            from keystoneclient import service_catalog
            service_catalog.ServiceCatalog.url_for = _management_url

        patch_management_url()

        try:
            if self._is_token_blacklisted(token):
                return False

            # Try to get the client's access information
            access_info = self._get_access_info(
                url,
                tenant,
                token,
                blacklist_ttl,
                max_cache_life
            )

            if access_info is None:
                LOG.debug(
                    'Unable to get Access information for %(s_tenant)s' % {
                        's_tenant': tenant
                    }
                )
                return False

            # provided data was valid,
            # insert the information into the environment
            env['HTTP_X_IDENTITY_STATUS'] = 'Confirmed'

            env['HTTP_X_USER_ID'] = access_info.user_id
            env['HTTP_X_USER_NAME'] = access_info.username
            env['HTTP_X_USER_DOMAIN_ID'] = access_info.user_domain_id
            env['HTTP_X_USER_DOMAIN_NAME'] = access_info.user_domain_name
            env['HTTP_X_ROLES'] = ','.join(
                role for role in access_info.role_names
            )
            if access_info.has_service_catalog():
                # Convert the service catalog to JSON
                service_catalog_data = json.dumps(
                    access_info.service_catalog.catalog)

                # convert service catalog to unicode to try to help
                # prevent encode/decode errors under python2
                if six.PY2:  # pragma: no cover
                    u_service_catalog_data = service_catalog_data.decode(
                        'utf-8'
                    )
                else:  # pragma: no cover
                    u_service_catalog_data = service_catalog_data

                # Convert the JSON string data to strict UTF-8
                utf8_data = u_service_catalog_data.encode(
                    encoding='utf-8', errors='strict')

                # Store it as Base64 for transport
                env['HTTP_X_SERVICE_CATALOG'] = base64.b64encode(utf8_data)

                try:
                    decode_check = base64.b64decode(
                        env['HTTP_X_SERVICE_CATALOG']
                    )

                except TypeError as te:
                    LOG.debug('Failed to decode the data properly')
                    LOG.info(te, exc_info=True)
                    return False

                if decode_check != utf8_data:
                    LOG.debug(
                        'Decode Check: decoded data does not match '
                        'encoded data'
                    )
                    return False

            # Project Scoped V3 or Tenant Scoped v2
            # This can be assumed since we validated using X_PROJECT_ID
            # and therefore have at least a v2 Tenant Scoped Token
            if access_info.project_scoped:
                env['HTTP_X_PROJECT_ID'] = access_info.project_id
                env['HTTP_X_PROJECT_NAME'] = access_info.project_name

            # Domain-Scoped V3
            if access_info.domain_scoped:
                env['HTTP_X_DOMAIN_ID'] = access_info.domain_id
                env['HTTP_X_DOMAIN_NAME'] = access_info.domain_name

            # Project-Scoped V3 - X_PROJECT_NAME is only unique
            # within the domain
            if access_info.project_scoped and (
                    access_info.domain_scoped):
                env['HTTP_X_PROJECT_DOMAIN_ID'] = access_info.project_domain_id
                env['HTTP_X_PROJECT_DOMAIN_NAME'] = (
                    access_info.project_domain_name
                )

            return True

        except Exception as ex:
            msg = (
                'Error while trying to authenticate against'
                ' %(s_url)s - %(s_except)s' % {
                    's_url': url,
                    's_except': str(ex)
                }
            )
            LOG.debug(msg)
            return False

    @staticmethod
    def _http_precondition_failed(start_response):
        """Responds with HTTP 412."""
        start_response('412 Precondition Failed', [('Content-Length', '0')])
        return []

    @staticmethod
    def _http_unauthorized(start_response):
        """Responds with HTTP 401."""
        start_response('401 Unauthorized', [('Content-Length', '0')])
        return []

    def __call__(self, env, start_response):
        """Wrap a WSGI app with Authentication middleware.

        :returns: a new  WSGI app that wraps the original
        """

        auth_url = self._auth_conf['auth_url']
        blacklist_ttl = self._auth_conf['blacklist_ttl']
        max_cache_life = self._auth_conf['max_cache_life']

        LOG.debug('Auth URL: {0:}'.format(auth_url))

        try:
            token = env['HTTP_X_AUTH_TOKEN']
            tenant = env['HTTP_X_PROJECT_ID']

            # validate the client and fill out the environment it's valid
            if self._validate_client(
                    auth_url,
                    tenant,
                    token,
                    env,
                    blacklist_ttl,
                    max_cache_life
            ):
                LOG.debug('Auth Token validated.')
                return self.app(env, start_response)
            else:
                # Validation failed for some reason, just error out as a 401
                LOG.error('Auth Token validation failed.')
                return self._http_unauthorized(start_response)
        except (KeyError, LookupError):
            # Header failure, error out with 412
            LOG.error('Missing required headers.')
            return self._http_precondition_failed(start_response)
