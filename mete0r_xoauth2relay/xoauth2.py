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

import logging

from attr import attrs
from attr import attrib
from twisted.internet import threads
from twisted.internet import defer
from twisted.internet.defer import inlineCallbacks
from twisted.internet.defer import returnValue
from twisted.mail.interfaces import IClientAuthentication
from twisted.mail.smtp import ESMTPSender
from twisted.mail.smtp import ESMTPSenderFactory
from twisted.logger import Logger
from zope.interface import implementer
from zope.interface import Interface


logger = logging.getLogger(__name__)


class IPasswordAcquirer(Interface):

    def acquirePassword(username):
        '''
        주어진 사용자 이름으로 패스워드를 얻는다.

        :returns: password deferred
        :rtype: Deferred
        '''


@implementer(IPasswordAcquirer)
@attrs
class XOAUTH2TokenAcquirer(object):

    logger = Logger()

    oauth2authenticator = attrib()

    @inlineCallbacks
    def acquirePassword(self, email):

        # https://developers.google.com/gmail/imap/xoauth2-protocol
        scope = 'https://mail.google.com'

        credentials = yield threads.deferToThread(
            self.oauth2authenticator.authenticate, email, scope,
        )

        if credentials is None:
            returnValue(None)
            return

        self.logger.info(
            'Credentials acquired: {credentials.access_token} (expiry: {credentials.token_expiry})',  # noqa
            credentials=credentials
        )
        returnValue(credentials.access_token)


@implementer(IClientAuthentication)
class XOAUTH2Authenticator(object):

    logger = Logger()

    def __init__(self, email):
        self.email = email

    def getName(self):
        return b'XOAUTH2'

    def challengeResponse(self, access_token, challenge):
        """
        Generate a challenge response string.
        """
        self.logger.info('challenge: {challenge}', challenge=challenge)
        return b'user=%s\x01auth=Bearer %s\x01\x01' % (
            self.email, access_token
        )


class XOAUTH2SMTPSender(ESMTPSender):

    def _registerAuthenticators(self):
        self.registerAuthenticator(XOAUTH2Authenticator(self.username))


class XOAUTH2SMTPSenderFactory(ESMTPSenderFactory):
    protocol = XOAUTH2SMTPSender


@attrs
class XOAUTH2MailerFactory(object):

    reactor = attrib()
    smtphost = attrib()
    port = attrib()
    tokenAcquirer = attrib()
    senderDomainName = attrib()

    def createMailer(self, email):
        return XOAUTH2Mailer(
            reactor=self.reactor,
            smtphost=self.smtphost,
            port=self.port,
            email=email,
            tokenAcquirer=self.tokenAcquirer,
            senderDomainName=self.senderDomainName,
        )


@attrs
class XOAUTH2Mailer(object):
    """
    Send an email.

    This interface is intended to be a replacement for L{smtplib.SMTP.sendmail}
    and related methods. To maintain backwards compatibility, it will fall back
    to plain SMTP, if ESMTP support is not available. If ESMTP support is
    available, it will attempt to provide encryption via STARTTLS and
    authentication if a secret is provided.

    @param smtphost: The host the message should be sent to.
    @type smtphost: L{bytes}

    @param senderDomainName: Name by which to identify. If None, try to pick
        something sane (but this depends on external configuration and may not
        succeed).
    @type senderDomainName: L{bytes}

    @param port: Remote port to which to connect.
    @type port: L{int}

    @param username: The username to use, if wanting to authenticate.
    @type username: L{bytes}

    @param password: The secret to use, if wanting to authenticate. If you do
        not specify this, SMTP authentication will not occur.
    @type password: L{bytes}

    @param requireTransportSecurity: Whether or not STARTTLS is required.
    @type requireTransportSecurity: L{bool}

    @param requireAuthentication: Whether or not authentication is required.
    @type requireAuthentication: L{bool}

    @param reactor: The L{reactor} used to make the TCP connection.
    """

    reactor = attrib()
    smtphost = attrib()
    port = attrib()
    email = attrib()
    tokenAcquirer = attrib()
    senderDomainName = attrib()

    heloFallback = False
    requireTransportSecurity = True
    requireAuthentication = True

    @inlineCallbacks
    def sendmail(self, to_addrs, msg):
        """
        Send an email.

        @param to_addrs:
            A list of addresses to send this mail to.  A string will be treated
            as a list of one address.
        @type to_addr:
            L{list} of L{bytes} or L{bytes}

        @param msg:
            The message, including headers, either as a file or a string.
            File-like objects need to support read() and close(). Lines must be
            delimited by '\\n'. If you pass something that doesn't look like a
            file, we try to convert it to a string (so you should be able to
            pass an L{email.message} directly, but doing the conversion with
            L{email.generator} manually will give you more control over the
            process).

        @rtype: L{Deferred}
        @returns:
            A cancellable L{Deferred}, its callback will be called if a message
            is sent to ANY address, the errback if no message is sent. When the
            C{cancel} method is called, it will stop retrying and disconnect
            the connection immediately.

            The callback will be called with a tuple (numOk, addresses) where
            numOk is the number of successful recipient addresses and addresses
            is a list of tuples (address, code, resp) giving the response to
            the RCPT command for each address.
        """
        from io import BytesIO
        from twisted.python.compat import networkString

        if not hasattr(msg, 'read'):
            # It's not a file
            msg = BytesIO(bytes(msg))

        access_token = yield self.tokenAcquirer.acquirePassword(self.email)

        def cancel(d):
            """
            Cancel the L{twisted.mail.smtp.sendmail} call, tell the factory
            not to retry and disconnect the connection.

            @param d: The L{defer.Deferred} to be cancelled.
            """
            factory.sendFinished = True
            if factory.currentProtocol:
                factory.currentProtocol.transport.abortConnection()
            else:
                # Connection hasn't been made yet
                connector.disconnect()

        d = defer.Deferred(cancel)
        factory = XOAUTH2SMTPSenderFactory(
            self.email,
            access_token,
            self.email,
            to_addrs,
            msg,
            d,
            heloFallback=self.heloFallback,
            requireAuthentication=self.requireAuthentication,
            requireTransportSecurity=self.requireTransportSecurity
        )

        if self.senderDomainName is not None:
            factory.domain = networkString(self.senderDomainName)

        connector = self.reactor.connectTCP(
            self.smtphost,
            self.port,
            factory
        )

        result = yield d
        returnValue(result)


if __name__ == '__main__':
    from .cli import main
    main()
