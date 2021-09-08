# -*- coding: utf-8 -*-
#
# Handlers dealing with client software exceptions
import json

from globaleaks.handlers.base import BaseHandler
from globaleaks.rest import requests
from globaleaks.utils.log import log


class ExceptionHandler(BaseHandler):
    """
    This handler is responsible of receiving exceptions by the client
    and delivering them to the configured exception mail.
    """
    check_roles = 'any'
    require_token = [b'POST']

    def post(self):
        request = self.validate_message(self.request.content.read(),
                                        requests.ExceptionDesc)

        exception_email = "URL: %s\n\n" % request['errorUrl']
        exception_email += "User Agent: %s\n\n" % request['agent']
        exception_email += "Error Message: %s\n\n" % request['errorMessage']
        exception_email += "Stacktrace:\n"
        exception_email += json.dumps(request['stackTrace'], indent=2)
        self.state.schedule_exception_email(self.request.tid, exception_email)
        log.debug("Received client exception and passed error to exception mail handler")
