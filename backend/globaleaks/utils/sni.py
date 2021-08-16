# -*- coding: utf-8 -*-

# This TLS SNI implementation is an extract of https://github.com/glyph/txsni
# For original authors and related LICENSE refer to the original repository
#
# The code is directly included into GlobaLeaks as the original library
# is currently not released as Debian package.

import collections

from OpenSSL.SSL import Connection
from twisted.internet.interfaces import IOpenSSLServerConnectionCreator
from zope.interface import implementer

from globaleaks.utils.tls import ChainValidator, TLSServerContextFactory, new_tls_server_context


class _NegotiationData(object):
    """
    A container for the negotiation data.
    """
    __slots__ = [
        'alpnSelectCallback',
        'alpnProtocols'
    ]

    def __init__(self):
        self.alpnSelectCallback = None
        self.alpnProtocols = None

    def negotiateALPN(self, context):
        if self.alpnSelectCallback is None or self.alpnProtocols is None:
            return

        context.set_alpn_select_callback(self.alpnSelectCallback)
        context.set_alpn_protos(self.alpnProtocols)


class _ContextProxy(object):
    """
    A basic proxy object for the OpenSSL Context object that records the
    values of the NPN/ALPN callbacks, to ensure that they get set appropriately
    if a context is swapped out during connection setup.
    """

    def __init__(self, original, factory):
        self._obj = original
        self._factory = factory

    def set_alpn_select_callback(self, cb):
        self._factory._alpnSelectCallbackForContext(self._obj, cb)
        return self._obj.set_alpn_select_callback(cb)

    def set_alpn_protos(self, protocols):
        self._factory._alpnProtocolsForContext(self._obj, protocols)
        return self._obj.set_alpn_protos(protocols)

    def __getattr__(self, attr):
        return getattr(self._obj, attr)

    def __setattr__(self, attr, val):
        if attr in ('_obj', '_factory'):
            self.__dict__[attr] = val

        return setattr(self._obj, attr, val)

    def __delattr__(self, attr):
        return delattr(self._obj, attr)


class _ConnectionProxy(object):
    """
    A basic proxy for an OpenSSL Connection object that returns a ContextProxy
    wrapping the actual OpenSSL Context whenever it's asked for.
    """

    def __init__(self, original, factory):
        self._obj = original
        self._factory = factory

    def get_context(self):
        """
        A basic override of get_context to ensure that the appropriate proxy
        object is returned.
        """
        return _ContextProxy(self._obj.get_context(), self._factory)

    def __getattr__(self, attr):
        return getattr(self._obj, attr)

    def __setattr__(self, attr, val):
        if attr in ('_obj', '_factory'):
            self.__dict__[attr] = val

        return setattr(self._obj, attr, val)

    def __delattr__(self, attr):
        return delattr(self._obj, attr)


@implementer(IOpenSSLServerConnectionCreator)
class SNIMap(object):
    default_context = None
    configs_by_tid = {}
    contexts_by_hostname = {}

    def __init__(self):
        self._negotiationDataForContext = collections.defaultdict(_NegotiationData)
        self.set_default_context(new_tls_server_context())

    def set_default_context(self, context):
        self.default_context = context
        self.default_context.set_tlsext_servername_callback(self.selectContext)

    def load(self, tid, conf):
        chnv = ChainValidator()
        ok, err = chnv.validate(conf, must_be_disabled=False, check_expiration=False)
        if not ok or err is not None:
            return

        self.configs_by_tid[tid] = conf

        context = TLSServerContextFactory(conf['ssl_key'],
                                          conf['ssl_cert'],
                                          conf['ssl_intermediate'])

        self.contexts_by_hostname[conf['hostname']] = context

        if tid == 1:
            self.set_default_context(context.getContext())

    def unload(self, tid):
        conf = self.configs_by_tid.pop(tid, None)
        if conf is not None:
            self.contexts_by_hostname.pop(conf['hostname'], None)

        if tid == 1:
            self.set_default_context(new_tls_server_context())

    def selectContext(self, connection):
        try:
            common_name = connection.get_servername().decode()
        except:
            common_name = ''

        if common_name in self.contexts_by_hostname:
            context = self.contexts_by_hostname[common_name].getContext()
        else:
            context = self.default_context

        negotiationData = self._negotiationDataForContext[connection.get_context()]
        negotiationData.negotiateNPN(context)
        negotiationData.negotiateALPN(context)
        connection.set_context(context)

    def serverConnectionForTLS(self, protocol):
        return _ConnectionProxy(Connection(self.default_context, None), self)

    def _alpnSelectCallbackForContext(self, context, callback):
        self._negotiationDataForContext[context].alpnSelectCallback = callback

    def _alpnProtocolsForContext(self, context, protocols):
        self._negotiationDataForContext[context].alpnProtocols = protocols
