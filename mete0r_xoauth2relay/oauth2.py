# -*- coding: utf-8 -*-
#
#   mete0r.xoauth2relay: SMTP XOAUTH2 Relay
#   Copyright (C) 2015-2017 mete0r <mete0r@sarangbang.or.kr>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

from datetime import datetime
from getpass import getpass
import logging
# import webbrowser

from attr import attrs
from attr import attrib
from httplib2 import Http
from zope.interface import Interface
from zope.interface import implementer
import oauth2client.client
import oauth2client.clientsecrets


logger = logging.getLogger(__name__)


class IClientSecetsStore(Interface):

    def load(project_id):
        '''
        Google API Project Client Secrets를 적재한다.

        :param project_id:
            Google API 프로젝트 식별자
        :returns: client_type, client_info
        :raises KeyError:
            주어진 프로젝트 식별자에 해당하는 Client Secrets가 없음
        '''

    def save(project_id, clientsecrets):
        '''
        Google API Project Client Secrets를 저장한다.

        :param project_id:
            Google API 프로젝트 식별자
        :param str clientsecrets:
            프로젝트 Client Secrets
        '''


@implementer(IClientSecetsStore)
@attrs
class ClientSecretsStore(object):

    keyring = attrib()

    @classmethod
    def create(cls):
        import keyring
        return cls(keyring)

    def load(self, project_id):
        s = self.keyring.get_password('Google API', project_id)
        if s is None:
            raise KeyError(project_id)
        return oauth2client.clientsecrets.loads(s)

    def save(self, project_id, clientsecrets):
        self.keyring.set_password('Google API', project_id, clientsecrets)


class ICredentialsStore(Interface):

    def save(email, credentials):
        pass

    def load(email):
        pass


@implementer(ICredentialsStore)
@attrs
class CredentialsStore(object):

    keyring = attrib()
    service = attrib()

    @classmethod
    def create(cls, service):
        import keyring
        return cls(keyring, service)

    def save(self, email, credentials):
        s = credentials.to_json()
        self.keyring.set_password(
            self.service, email, s
        )

    def load(self, email):
        s = self.keyring.get_password(
            self.service, email,
        )
        if s is None:
            return None
        return oauth2client.client.OAuth2Credentials.from_json(s)


class IOAuth2Authenticator(Interface):

    def authenticate(email, scope):
        pass


@implementer(IOAuth2Authenticator)
@attrs
class OAuth2Authenticator(object):

    client_type = attrib()
    client_info = attrib()

    @classmethod
    def create(cls, project_id):
        clientsecrets_store = ClientSecretsStore.create()
        client_type, client_info = clientsecrets_store.load(project_id)
        return cls(client_type, client_info)

    def authenticate(self, email, scope):
        redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
        login_hint = email
        if self.client_type not in (
            oauth2client.clientsecrets.TYPE_WEB,
            oauth2client.clientsecrets.TYPE_INSTALLED
        ):
            raise oauth2client.client.UnknownClientSecretsFlowError(
                self.client_type
            )
        kwargs = {
            'redirect_uri': redirect_uri,
            'auth_uri': self.client_info['auth_uri'],
            'token_uri': self.client_info['token_uri'],
            'login_hint': login_hint,
        }
        flow = oauth2client.client.OAuth2WebServerFlow(
            self.client_info['client_id'],
            self.client_info['client_secret'],
            scope,
            **kwargs
        )

        auth_uri = flow.step1_get_authorize_url()
        logger.info('Browse to %s', auth_uri)
        # webbrowser.open_new(auth_uri)

        auth_code = getpass('Auth code: ')
        return flow.step2_exchange(auth_code)


@implementer(IOAuth2Authenticator)
@attrs
class OAuth2AuthenticatorWithStore(object):

    oauth2authenticator = attrib()
    credentials_store = attrib()

    def authenticate(self, email, scope):
        credentials_store = self.credentials_store
        credentials = credentials_store.load(email)
        if credentials is not None:
            if credentials.token_expiry < datetime.utcnow():
                http = Http()
                credentials.refresh(http)
                credentials_store.save(email, credentials)
            return credentials

        credentials = self.oauth2authenticator.authenticate(email, scope)

        credentials_store.save(email, credentials)
        return credentials


@implementer(IOAuth2Authenticator)
@attrs
class OAuth2AuthenticatorRefreshingOnly(object):

    credentials_store = attrib()

    def authenticate(self, email, scope):
        credentials_store = self.credentials_store
        credentials = credentials_store.load(email)
        if credentials is not None:
            if credentials.token_expiry < datetime.utcnow():
                http = Http()
                credentials.refresh(http)
                credentials_store.save(email, credentials)
            return credentials
        return None
