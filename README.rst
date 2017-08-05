mete0r.xoauth2relay
===================

SMTP XOAUTH2 Relay


Usage
-----

Make a Google API Project and import clientsecrets.json file::

   xoauth2relay-init clientsecrets.json

Then login::

   xoauth2relay-login foo@gmail.com

You can login another account::

   xoauth2relay-login bar@gmail.com

Run the application::

   twistd -n -y xoauth2relay.tac

Now you can test it with a SMTP client::

   telnet localhost 2500


Development environment
-----------------------

To setup development environment::

   python setup.py virtualenv
   make
