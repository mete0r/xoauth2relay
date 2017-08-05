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

from attr import attrs
from attr import attrib
from twisted.internet.defer import inlineCallbacks
from twisted.internet.defer import returnValue
from twisted.logger import Logger
from twisted.mail import smtp
from zope.interface import implementer


@implementer(smtp.IMessageDeliveryFactory)
@attrs
class MessageDeliveryFactory(object):

    logger = Logger()
    mailerFactory = attrib()

    def getMessageDelivery(self):
        return MessageDelivery(self.mailerFactory)


@implementer(smtp.IMessageDelivery)
@attrs
class MessageDelivery(object):

    logger = Logger()

    mailerFactory = attrib()

    def receivedHeader(self, helo, origin, recipients):
        self.logger.info(
            'receivedHeader: helo={helo!r} origin={origin!r} recipients={recipients!r}',  # noqa
            helo=helo, origin=origin, recipients=recipients
        )
        self.origin = origin
        self.recipients = recipients

    @inlineCallbacks
    def validateFrom(self, helo, origin):
        self.logger.info(
            'validateFrom: helo={helo!r} origin={origin!r}',
            helo=helo,
            origin=origin,
        )

        accessToken = yield self.mailerFactory.tokenAcquirer.acquirePassword(
            str(origin),
        )
        if accessToken is None:
            self.logger.error('accessToken cannot be acquired')
            raise smtp.SMTPBadSender(origin)
        self.logger.info('accessToken can be acquired')

        self.mailer = self.mailerFactory.createMailer(str(origin))
        returnValue(origin)

    def validateTo(self, user):
        self.logger.info(
            'validateTo: dest={user.dest!r} orig={user.orig!r}',
            user=user,
        )
        return lambda: MessageSMTP(self.mailer, user.dest)


@implementer(smtp.IMessage)
class MessageSMTP(object):

    logger = Logger()

    def __init__(self, mailer, dest):
        self.mailer = mailer
        self.dest = dest
        self.lines = []

    def lineReceived(self, line):
        self.lines.append(line)

    def eomReceived(self):
        self.logger.info('New message received:')
        data = b'\n'.join(self.lines)
        self.lines = None
        self.logger.info('{lines!r}', lines=data)
        return self.mailer.sendmail(
            [self.dest.addrstr],
            data,
        )

    def connectionLost(self):
        self.lines = None


class SMTPServerProtocolFactory(smtp.SMTPFactory):

    protocol = smtp.SMTP

    def __init__(self, deliveryFactory, *args, **kwargs):
        smtp.SMTPFactory.__init__(self, *args, **kwargs)
        self.deliveryFactory = deliveryFactory

    def buildProtocol(self, addr):
        protocol = smtp.SMTPFactory.buildProtocol(self, addr)
        protocol.deliveryFactory = self.deliveryFactory
        return protocol


def make_application(remoteHost, remotePort, listenPort, bindAddress):
    from twisted.application.internet import TCPServer
    from twisted.application.service import Application
    from twisted.internet import reactor

    applicationName = 'xoauth2relay'
    application = Application(applicationName)

    from .oauth2 import CredentialsStore
    from .oauth2 import OAuth2AuthenticatorRefreshingOnly
    from .xoauth2 import XOAUTH2TokenAcquirer
    from .xoauth2 import XOAUTH2MailerFactory

    credentialsStore = CredentialsStore.create(applicationName)
    oauth2authenticator = OAuth2AuthenticatorRefreshingOnly(
        credentialsStore,
    )

    tokenAcquirer = XOAUTH2TokenAcquirer(
        oauth2authenticator=oauth2authenticator,
    )

    mailerFactory = XOAUTH2MailerFactory(
        reactor,
        remoteHost,
        remotePort,
        tokenAcquirer,
        None,
    )
    smtpDeliveryFactory = MessageDeliveryFactory(mailerFactory=mailerFactory)
    smtpServerProtoFactory = SMTPServerProtocolFactory(
        deliveryFactory=smtpDeliveryFactory,
    )
    smtpServer = TCPServer(
        listenPort,
        smtpServerProtoFactory,
        interface=bindAddress
    )
    smtpServer.setServiceParent(application)
    return application
