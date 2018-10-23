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
from __future__ import print_function
from __future__ import unicode_literals
from argparse import ArgumentParser
from datetime import datetime
import gettext
import io
import json
import logging
import os.path
import sys

# PYTHON_ARGCOMPLETE_OK
try:
    import argcomplete
except ImportError:
    argcomplete = None

from . import __version__
from .twistedapp import make_application

PY3 = sys.version_info.major == 3
logger = logging.getLogger(__name__)

locale_dir = os.path.join(os.path.dirname(__file__), 'locale')
t = gettext.translation('mete0r.xoauth2relay', locale_dir, fallback=True)
if PY3:
    _ = t.gettext
else:
    _ = t.ugettext


def init():
    gettext.gettext = t.gettext
    parser = init_argparse()
    if argcomplete:
        argcomplete.autocomplete(parser)
    args = parser.parse_args()
    configureLogging(args.verbose)
    logger.debug('args: %s', args)

    app_name = 'xoauth2relay'

    from keyring import get_keyring
    keyring = get_keyring()

    from .oauth2 import ClientSecretsStore
    clientsecrets_store = ClientSecretsStore(keyring)
    try:
        client_type, client_info = clientsecrets_store.load(
            app_name,
        )
    except KeyError:
        pass
    else:
        if not args.force:
            logger.warning('clientsecrets already exists; ignoring')
            return

    try:
        with io.open(args.clientsecrets, 'rb') as fp:
            clientsecrets = fp.read()
            json.loads(clientsecrets)
    except IOError as e:
        logger.error(e)
        raise SystemExit(1)
    clientsecrets_store.save(app_name, clientsecrets)
    logger.info('clientsecrets saved.')
    if args.delete:
        os.unlink(args.clientsecrets)
        logger.info('deleted: %s', args.clientsecrets)


def init_argparse():
    parser = ArgumentParser()
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s {}'.format(__version__),
        help=_('output version information and exit')
    )
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        help=_('increase verbosity')
    )
    parser.add_argument(
        'clientsecrets',
        help=_('Google API Project Client Secrets file'),
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help=_('Overwrite existing client secrets.'),
    )
    parser.add_argument(
        '--delete',
        action='store_true',
        help=_('Delete imported client secrets file.'),
    )
    return parser


def login():
    gettext.gettext = t.gettext
    parser = login_argparse()
    if argcomplete:
        argcomplete.autocomplete(parser)
    args = parser.parse_args()
    configureLogging(args.verbose)
    logger.debug('args: %s', args)

    from keyring import get_keyring
    from httplib2 import Http
    from .oauth2 import CredentialsStore
    from .oauth2 import ClientSecretsStore
    from .oauth2 import OAuth2Authenticator

    app_name = 'xoauth2relay'
    email = args.email

    keyring = get_keyring()
    credentials_store = CredentialsStore(keyring, app_name)
    credentials = credentials_store.load(email)
    if credentials is not None and not args.force_authenticate:
        if credentials.token_expiry < datetime.utcnow():
            logger.info('OAuth2 token has been expired.')
            http = Http()
            credentials.refresh(http)
            credentials_store.save(email, credentials)
            logger.info('OAuth2 token has been refreshed.')
        else:
            logger.info('OAuth2 token already exists.')
        return

    clientsecrets_store = ClientSecretsStore(keyring)
    try:
        client_type, client_info = clientsecrets_store.load(
            app_name,
        )
    except KeyError:
        logger.error('clientsecrets not found')
        raise SystemExit(1)

    oauth2authenticator = OAuth2Authenticator(
        client_type, client_info,
    )
    scope = 'https://mail.google.com'
    credentials = oauth2authenticator.authenticate(
        email, scope,
    )
    credentials_store.save(email, credentials)
    logger.info('OAuth2 token saved.')


def login_argparse():
    parser = ArgumentParser()
    parser.add_argument('--version',
                        action='version',
                        version='%(prog)s {}'.format(__version__),
                        help=_('output version information and exit'))
    parser.add_argument('-v', '--verbose',
                        action='count',
                        help=_('increase verbosity'))
    parser.add_argument(
        'email',
        help=_('GMail login email'),
    )
    parser.add_argument(
        '--force-authenticate',
        action='store_true',
        help=_('Force authentication'),
    )
    return parser


def serve():
    gettext.gettext = t.gettext
    parser = serve_argparse()
    if argcomplete:
        argcomplete.autocomplete(parser)
    args = parser.parse_args()
    configureLogging(args.verbose)
    logger.debug('args: %s', args)

    from twisted.internet import reactor
    from twisted.application.service import IService
    application = make_application(
            remoteHost='smtp.gmail.com',
            remotePort=587,
            listenPort=int(args.port),
            bindAddress=args.bind,
    )

    def onStartUp():
        logger.info('Starting service')
        IService(application).startService()

    def onShutdown():
        logger.info('Stopping service')
        IService(application).stopService()

    reactor.addSystemEventTrigger(
        'before',
        'startup',
        onStartUp,
    )


    reactor.addSystemEventTrigger(
        'before',
        'shutdown',
        onShutdown,
    )


    reactor.run()


def serve_argparse():
    parser = ArgumentParser()
    parser.add_argument('--version',
                        action='version',
                        version='%(prog)s {}'.format(__version__),
                        help=_('output version information and exit'))
    parser.add_argument('-v', '--verbose',
                        action='count',
                        help=_('increase verbosity'))
    parser.add_argument(
        '--bind',
        action='store',
        default='127.0.0.1',
        help=_('Local binding address'),
    )
    parser.add_argument(
        '--port',
        action='store',
        default='2500',
        help=_('Local listening port'),
    )
    return parser


def configureLogging(verbosity):
    if verbosity == 1:
        level = logging.DEBUG
    elif verbosity > 1:
        level = logging.DEBUG
    else:
        level = logging.INFO
    try:
        import coloredlogs
    except ImportError:
        logging.basicConfig(level=level)
    else:
        coloredlogs.install(level)
