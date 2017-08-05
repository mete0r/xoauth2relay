# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function
import os
import sys

sys.path[0:0] = [os.getcwd()]


from mete0r_xoauth2relay.twistedapp import make_application  # noqa
application = make_application(
	remoteHost='smtp.gmail.com',
	remotePort=587,
	listenPort=2500,
	bindAddress='localhost',
)
