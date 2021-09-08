# -*- coding: utf-8 -*-
from globaleaks import models
from globaleaks.handlers import exception
from globaleaks.tests import helpers
from twisted.internet.defer import inlineCallbacks


class TestExceptionHandler(helpers.TestHandler):
    _handler = exception.ExceptionHandler

    @inlineCallbacks
    def test_post(self):
        exception_data = {
            'errorUrl': 'https://www.globaleaks.org/exception',
            'errorMessage': 'EXCEPTION!',
            'stackTrace': [],
            'agent': "Antani 1.3.3.7"
        }

        yield self.test_model_count(models.Mail, 0)
        handler = self.request(exception_data)
        yield handler.post()
        self.assertEqual(handler.request.code, 200)
        yield self.test_model_count(models.Mail, 1)
