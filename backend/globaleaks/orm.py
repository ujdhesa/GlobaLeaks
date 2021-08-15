# -*- coding: utf-8
import collections
import random
import time
import warnings

from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError, SAWarning
from sqlalchemy.orm import sessionmaker

from twisted.internet import reactor
from twisted.internet.threads import deferToThreadPool

_DEBUG = False
_DB_URI = 'sqlite:'
_THREAD_POOL = None

TRANSACTION_RETRIES = 20


warnings.filterwarnings('ignore', '.', SAWarning)


def make_db_uri(db_file):
    return 'sqlite:////' + db_file


def set_db_uri(db_uri):
    global _DB_URI
    _DB_URI = db_uri


def get_db_uri():
    return _DB_URI


def get_engine(db_uri=None, foreign_keys=True):
    if db_uri is None:
        db_uri = get_db_uri()

    engine = create_engine(db_uri, connect_args={'timeout': 30}, echo=_DEBUG)

    @event.listens_for(engine, "connect")
    def do_connect(conn, connection_record):
        if foreign_keys:
            conn.execute('pragma foreign_keys=ON')

    return engine


def get_session(db_uri=None, foreign_keys=True):
    return sessionmaker(bind=get_engine(db_uri, foreign_keys))()



def enable_orm_debug():
    global _DEBUG
    _DEBUG = True


def set_thread_pool(thread_pool):
    global _THREAD_POOL
    _THREAD_POOL = thread_pool


def get_thread_pool():
    return _THREAD_POOL


def db_add(session, model_class, model_fields):
    obj = model_class(model_fields)
    if not obj.id:
        session.add(obj)
        session.flush()
    else:
        session.merge(obj)
    return obj


def db_query(session, selector, filter=None):
    if isinstance(selector, collections.Iterable):
        q = session.query(*selector)
    else:
        q = session.query(selector)

    if filter is None:
        return q

    if isinstance(filter, collections.Iterable):
        return q.filter(*filter)
    else:
        return q.filter(filter)


def db_get(session, selector, filter=None):
    return db_query(session, selector, filter).one()


def db_del(session, selector, filter=None):
    db_query(session, selector, filter).delete(synchronize_session=False)


class transact(object):
    """
    Class decorator for managing transactions.
    """

    def __init__(self, method):
        self.method = method
        self.instance = None

    def __get__(self, instance, owner):
        self.instance = instance
        return self

    def __call__(self, *args, **kwargs):
        return self.run(self._wrap, self.method, *args, **kwargs)

    def run(self, function, *args, **kwargs):
        return deferToThreadPool(reactor,
                                 get_thread_pool(),
                                 function,
                                 *args,
                                 **kwargs)

    def _wrap(self, function, *args, **kwargs):
        """
        Wrap provided function calling it inside a thread and
        passing the ORM session to it.
        """
        session = get_session()
        retries = 0

        try:
            while True:
                try:
                    if self.instance:
                        result = function(self.instance, session, *args, **kwargs)
                    else:
                        result = function(session, *args, **kwargs)

                    session.commit()
                except OperationalError as e:
                    session.rollback()

                    if "database is locked" not in str(e):
                        raise

                    retries += 1

                    if retries >= TRANSACTION_RETRIES:
                        raise Exception("Transaction failed with too many retries")

                    time.sleep(0.2 * random.uniform(1, 2 ** retries))
                except:
                    session.rollback()
                    raise
                else:
                    return result
        finally:
            session.close()


class transact_sync(transact):
    def run(self, function, *args, **kwargs):
        return function(*args, **kwargs)


@transact
def tw(session, f, *args, **kwargs):
    return f(session, *args, **kwargs)
