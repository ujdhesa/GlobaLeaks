# -*- coding: utf-8 -*-
"""
ORM Models definitions.
"""
import copy

from globaleaks.models import config_desc
from globaleaks.models.enums import *
from globaleaks.models.properties import *
from globaleaks.rest import errors
from globaleaks.utils.utility import datetime_now, datetime_never, datetime_null


class LocalizationEngine(object):
    """
    This Class can manage all the localized strings inside one ORM object
    """
    def __init__(self, keys):
        self._localized_strings = {}
        self._localized_keys = keys

    def acquire_orm_object(self, obj):
        self._localized_strings = {key: getattr(obj, key) for key in self._localized_keys}

    def acquire_multilang_dict(self, obj):
        self._localized_strings = {}
        for key in self._localized_keys:
            value = obj[key] if key in obj else ''
            self._localized_strings[key] = value

    def singlelang_to_multilang_dict(self, obj, language):
        ret = {}

        for key in self._localized_keys:
            ret[key] = {language: obj[key]} if key in obj else {language: ''}

        return ret

    def dump_localized_key(self, key, language):
        if key not in self._localized_strings:
            return ""

        translated_dict = self._localized_strings[key]

        if not isinstance(translated_dict, dict):
            return ""

        if language is None:
            # When language is None we export the full language dictionary
            return translated_dict
        elif language in translated_dict:
            return translated_dict[language]
        elif 'en' in translated_dict:
            return translated_dict['en']
        else:
            return ""


def fill_localized_keys(dictionary, keys, language):
    if language is not None:
        mo = LocalizationEngine(keys)
        multilang_dict = mo.singlelang_to_multilang_dict(dictionary, language)
        dictionary.update({key: multilang_dict[key] for key in keys})

    return dictionary


def get_localized_values(dictionary, obj, keys, language):
    mo = LocalizationEngine(keys)

    if isinstance(obj, dict):
        mo.acquire_multilang_dict(obj)
    elif isinstance(obj, Model):
        mo.acquire_orm_object(obj)

    if language is not None:
        dictionary.update({key: mo.dump_localized_key(key, language) for key in keys})
    else:
        for key in keys:
            value = mo._localized_strings[key] if key in mo._localized_strings else ''
            dictionary.update({key: value})

    return dictionary


Base = declarative_base()


class Model(object):
    """
    Base ORM model
    """
    # initialize empty list for the base classes
    properties = []
    unicode_keys = []
    localized_keys = []
    int_keys = []
    bool_keys = []
    datetime_keys = []
    json_keys = []
    date_keys = []
    optional_references = []
    list_keys = []

    def __init__(self, values=None):
        self.update(values)

        self.properties = self.__table__.columns._data.keys()

    def update(self, values=None):
        """
        Updated Models attributes from dict.
        """
        if values is None:
            return

        if 'id' in values and values['id']:
            setattr(self, 'id', values['id'])

        if 'tid' in values and values['tid']:
            setattr(self, 'tid', values['tid'])

        for k in getattr(self, 'unicode_keys'):
            if k in values and values[k] is not None:
                setattr(self, k, values[k])

        for k in getattr(self, 'int_keys'):
            if k in values and values[k] is not None:
                setattr(self, k, int(values[k]))

        for k in getattr(self, 'datetime_keys'):
            if k in values and values[k] is not None:
                setattr(self, k, values[k])

        for k in getattr(self, 'bool_keys'):
            if k in values and values[k] is not None:
                if values[k] == 'true':
                    value = True
                elif values[k] == 'false':
                    value = False
                else:
                    value = bool(values[k])
                setattr(self, k, value)

        for k in getattr(self, 'localized_keys'):
            if k in values and values[k] is not None:
                value = values[k]
                previous = copy.deepcopy(getattr(self, k))

                if previous and isinstance(previous, dict):
                    previous.update(value)
                    value = previous

                setattr(self, k, value)

        for k in getattr(self, 'json_keys'):
            if k in values and values[k] is not None:
                setattr(self, k, values[k])

        for k in getattr(self, 'optional_references'):
            if k in values and values[k]:
                setattr(self, k, values[k])

    def __setattr__(self, name, value):
        if isinstance(value, bytes):
            value = value.decode()

        return super(Model, self).__setattr__(name, value)

    def dict(self, language=None):
        """
        Return a dictionary serialization of the current model.
        """
        ret = {}

        for k in self.properties:
            value = getattr(self, k)

            if value is not None:
                if k in self.localized_keys:
                    if language is not None:
                        ret[k] = value[language] if language in value else ''
                    else:
                        ret[k] = value

                elif k in self.date_keys:
                    ret[k] = value
            else:
                if self.__table__.columns[k].default and not callable(self.__table__.columns[k].default.arg):
                    ret[k] = self.__table__.columns[k].default.arg
                else:
                    ret[k] = ''

        for k in self.list_keys:
            ret[k] = []

        return ret


class _ArchivedSchema(Model):
    __tablename__ = 'archivedschema'

    hash = Column(UnicodeText(64), primary_key=True)
    schema = Column(JSON, default=dict, nullable=False)

    unicode_keys = ['hash']


class _Comment(Model):
    """
    This table handle the comment collection, has an InternalTip referenced
    """
    __tablename__ = 'comment'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4, nullable=False)
    creation_date = Column(DateTime, default=datetime_now, nullable=False)
    internaltip_id = Column(UnicodeText(36), nullable=False)
    author_id = Column(UnicodeText(36))
    content = Column(UnicodeText, nullable=False)
    type = Column(UnicodeText, nullable=False)
    new = Column(Boolean, default=True, nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['internaltip_id'], ['internaltip.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _Config(Model):
    __tablename__ = 'config'
    tid = Column(Integer, primary_key=True, default=1)
    var_name = Column(UnicodeText(64), primary_key=True)
    value = Column(JSON, default=dict, nullable=False)
    update_date = Column(DateTime, default=datetime_null, nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)

    def __init__(self, values=None):
        """
        :param values:   This input is passed directly into set_v
        """
        if values is None:
            return

        self.tid = values['tid']
        self.var_name = values['var_name']
        self.set_v(values['value'])

    def set_v(self, val):
        desc = config_desc.ConfigDescriptor[self.var_name]
        if val is None:
            val = desc._type()

        if isinstance(val, bytes):
            val = val.decode()

        if not isinstance(val, desc._type):
            raise ValueError("Cannot assign %s with %s" % (self, type(val)))

        if self.value != val:
            if self.value is not None:
                self.update_date = datetime_now()

            self.value = val


class _ConfigL10N(Model):
    __tablename__ = 'config_l10n'

    tid = Column(Integer, primary_key=True, default=1)
    lang = Column(UnicodeText(12), primary_key=True)
    var_name = Column(UnicodeText(64), primary_key=True)
    value = Column(UnicodeText, nullable=False)
    update_date = Column(DateTime, default=datetime_null, nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid', 'lang'], ['enabledlanguage.tid', 'enabledlanguage.name'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)

    def __init__(self, values=None):
        if values is None:
            return

        self.tid = values['tid']
        self.lang = values['lang']
        self.var_name = values['var_name']
        self.value = values['value']

    def set_v(self, value):
        if self.value != value:
            if self.value is not None:
                self.update_date = datetime_now()

            self.value = value


class _Context(Model):
    """
    This model keeps track of contexts settings.
    """
    __tablename__ = 'context'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    tid = Column(Integer, default=1, nullable=False)
    show_steps_navigation_interface = Column(Boolean, default=True, nullable=False)
    show_recipients_details = Column(Boolean, default=False, nullable=False)
    allow_recipients_selection = Column(Boolean, default=False, nullable=False)
    maximum_selectable_receivers = Column(Integer, default=0, nullable=False)
    select_all_receivers = Column(Boolean, default=True, nullable=False)
    enable_comments = Column(Boolean, default=True, nullable=False)
    enable_messages = Column(Boolean, default=False, nullable=False)
    enable_two_way_comments = Column(Boolean, default=True, nullable=False)
    enable_two_way_messages = Column(Boolean, default=True, nullable=False)
    enable_attachments = Column(Boolean, default=True, nullable=False)
    enable_rc_to_wb_files = Column(Boolean, default=False, nullable=False)
    tip_timetolive = Column(Integer, default=90, nullable=False)
    name = Column(JSON, default=dict, nullable=False)
    description = Column(JSON, default=dict, nullable=False)
    show_receivers_in_alphabetical_order = Column(Boolean, default=True, nullable=False)
    score_threshold_high = Column(Integer, default=0, nullable=False)
    score_threshold_medium = Column(Integer, default=0, nullable=False)
    score_receipt_text_custom = Column(Boolean, default=False, nullable=False)
    score_receipt_text_l = Column(JSON, default=dict, nullable=False)
    score_receipt_text_m = Column(JSON, default=dict, nullable=False)
    score_receipt_text_h = Column(JSON, default=dict, nullable=False)
    score_threshold_receipt = Column(Integer, default=0, nullable=False)
    questionnaire_id = Column(UnicodeText(36), default='default', nullable=False)
    additional_questionnaire_id = Column(UnicodeText(36))
    languages = Column(UnicodeText, default='', nullable=False)
    status = Column(Enum(EnumContextStatus), default='hidden', nullable=False)
    order = Column(Integer, default=0, nullable=False)

    unicode_keys = [
        'questionnaire_id',
        'additional_questionnaire_id',
        'languages',
        'status'
    ]

    localized_keys = [
        'name',
        'description',
        'score_receipt_text_l',
        'score_receipt_text_m',
        'score_receipt_text_h'
    ]

    int_keys = [
        'tip_timetolive',
        'maximum_selectable_receivers',
        'order',
        'score_threshold_high',
        'score_threshold_medium',
        'score_threshold_receipt',
    ]

    bool_keys = [
        'select_all_receivers',
        'show_context',
        'show_recipients_details',
        'show_receivers_in_alphabetical_order',
        'show_steps_navigation_interface',
        'allow_recipients_selection',
        'enable_comments',
        'enable_messages',
        'enable_two_way_comments',
        'enable_two_way_messages',
        'enable_attachments',
        'enable_rc_to_wb_files',
        'score_receipt_text_custom'
    ]

    list_keys = ['receivers']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                ForeignKeyConstraint(['questionnaire_id'], ['questionnaire.id'], deferrable=True, initially='DEFERRED'),
                CheckConstraint(self.status.in_(EnumContextStatus.keys())))


class _CustomTexts(Model):
    """
    Class used to implement custom texts
    """
    __tablename__ = 'customtexts'

    tid = Column(Integer, default=1, primary_key=True)
    lang = Column(UnicodeText(12), primary_key=True)
    texts = Column(JSON, default=dict, nullable=False)

    unicode_keys = ['lang']
    json_keys = ['texts']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _EnabledLanguage(Model):
    __tablename__ = 'enabledlanguage'

    tid = Column(Integer, primary_key=True, default=1, nullable=False)
    name = Column(UnicodeText(12), primary_key=True, nullable=False)

    unicode_keys = ['name']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _Field(Model):
    __tablename__ = 'field'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    tid = Column(Integer, default=1, nullable=False)
    x = Column(Integer, default=0, nullable=False)
    y = Column(Integer, default=0, nullable=False)
    width = Column(Integer, default=0, nullable=False)
    label = Column(JSON, default=dict, nullable=False)
    description = Column(JSON, default=dict, nullable=False)
    hint = Column(JSON, default=dict, nullable=False)
    placeholder = Column(JSON, default=dict, nullable=False)
    required = Column(Boolean, default=False, nullable=False)
    preview = Column(Boolean, default=False, nullable=False)
    multi_entry = Column(Boolean, default=False, nullable=False)
    triggered_by_score = Column(Integer, default=0, nullable=False)
    step_id = Column(UnicodeText(36))
    fieldgroup_id = Column(UnicodeText(36))
    type = Column(UnicodeText, default='inputbox', nullable=False)
    instance = Column(Enum(EnumFieldInstance), default='instance', nullable=False)
    template_id = Column(UnicodeText(36))
    template_override_id = Column(UnicodeText(36), nullable=True)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                ForeignKeyConstraint(['step_id'], ['step.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                ForeignKeyConstraint(['fieldgroup_id'], ['field.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                ForeignKeyConstraint(['template_id'], ['field.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                ForeignKeyConstraint(['template_override_id'], ['field.id'], ondelete='SET NULL', deferrable=True, initially='DEFERRED'),
                CheckConstraint(self.instance.in_(EnumFieldInstance.keys())))

    unicode_keys = ['type', 'instance', 'key']
    int_keys = ['x', 'y', 'width', 'triggered_by_score']
    localized_keys = ['label', 'description', 'hint', 'placeholder']
    bool_keys = ['multi_entry', 'preview', 'required']
    optional_references = ['template_id', 'step_id', 'fieldgroup_id', 'template_override_id']


class _FieldAttr(Model):
    __tablename__ = 'fieldattr'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4, nullable=False)
    field_id = Column(UnicodeText(36), nullable=False)
    name = Column(UnicodeText, nullable=False)
    type = Column(Enum(EnumFieldAttrType), nullable=False)
    value = Column(JSON, default=dict, nullable=False)

    unicode_keys = ['field_id', 'name', 'type']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['field_id'], ['field.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                CheckConstraint(self.type.in_(EnumFieldAttrType.keys())))

    def update(self, values=None):
        super(_FieldAttr, self).update(values)

        if values is None:
            return

        value = values['value']

        if self.type == 'localized':
            previous = getattr(self, 'value')
            if previous and isinstance(previous, dict):
                previous = copy.deepcopy(previous)
                previous.update(value)
                value = previous

        self.value = value


class _FieldOption(Model):
    __tablename__ = 'fieldoption'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4, nullable=False)
    field_id = Column(UnicodeText(36), nullable=False)
    order = Column(Integer, default=0, nullable=False)
    label = Column(JSON, default=dict, nullable=False)
    hint1 = Column(JSON, default=dict, nullable=False)
    hint2 = Column(JSON, default=dict, nullable=False)
    score_points = Column(Integer, default=0, nullable=False)
    score_type = Column(Enum(EnumFieldOptionScoreType), default='addition', nullable=False)
    block_submission = Column(Boolean, default=False, nullable=False)
    trigger_receiver = Column(JSON, default=list, nullable=False)

    unicode_keys = ['field_id']
    bool_keys = ['block_submission']
    int_keys = ['order', 'score_points']
    json_keys = ['trigger_receiver']
    localized_keys = ['hint1', 'hint2', 'label']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['field_id'], ['field.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _FieldOptionTriggerField(Model):
    __tablename__ = 'fieldoptiontriggerfield'

    option_id = Column(UnicodeText(36), primary_key=True)
    object_id = Column(UnicodeText(36), primary_key=True)
    sufficient = Column(Boolean, default=True, nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['option_id'], ['fieldoption.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                ForeignKeyConstraint(['object_id'], ['field.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'))


class _FieldOptionTriggerStep(Model):
    __tablename__ = 'fieldoptiontriggerstep'

    option_id = Column(UnicodeText(36), primary_key=True, nullable=False)
    object_id = Column(UnicodeText(36), primary_key=True, nullable=False)
    sufficient = Column(Boolean, default=True, nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['option_id'], ['fieldoption.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                ForeignKeyConstraint(['object_id'], ['step.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'))


class _File(Model):
    """
    Class used for storing files
    """
    __tablename__ = 'file'

    tid = Column(Integer, default=1)
    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    name = Column(UnicodeText, default='', nullable=False)

    unicode_keys = ['name']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                UniqueConstraint('tid', 'name'))


class _AuditLog(Model):
    """
    This model contains audit logs
    """
    __tablename__ = 'auditlog'

    tid = Column(Integer, default=1)
    id = Column(UnicodeText(36), primary_key=True, default=uuid4, nullable=False)
    date = Column(DateTime, default=datetime_now, nullable=False)
    type = Column(UnicodeText(24), default='', nullable=False)
    severity = Column(Integer, default=0, nullable=False)
    user_id = Column(UnicodeText(36), nullable=True)
    object_id = Column(UnicodeText(36), nullable=True)
    data = Column(JSON, nullable=True)


class _IdentityAccessRequest(Model):
    """
    This model keeps track of identity access requests by receivers and
    of the answers by custodians.
    """
    __tablename__ = 'identityaccessrequest'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4, nullable=False)

    receivertip_id = Column(UnicodeText(36), nullable=False)
    request_date = Column(DateTime, default=datetime_now, nullable=False)
    request_motivation = Column(UnicodeText, default='')
    reply_date = Column(DateTime, default=datetime_null, nullable=False)
    reply_user_id = Column(UnicodeText(36), default='', nullable=False)
    reply_motivation = Column(UnicodeText, default='', nullable=False)
    reply = Column(UnicodeText, default='pending', nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['receivertip_id'], ['receivertip.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _InternalFile(Model):
    """
    This model keeps track of submission files
    """
    __tablename__ = 'internalfile'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)

    creation_date = Column(DateTime, default=datetime_now, nullable=False)
    internaltip_id = Column(UnicodeText(36), nullable=False)
    name = Column(UnicodeText, nullable=False)
    filename = Column(UnicodeText, default='', nullable=False)
    content_type = Column(JSON, default='', nullable=False)
    size = Column(JSON, default='', nullable=False)
    new = Column(Boolean, default=True, nullable=False)
    submission = Column(Integer, default=False, nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['internaltip_id'], ['internaltip.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _InternalTip(Model):
    """
    This is the internal representation of a Tip that has been submitted
    """
    __tablename__ = 'internaltip'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    tid = Column(Integer, default=1, nullable=False)
    creation_date = Column(DateTime, default=datetime_now, nullable=False)
    update_date = Column(DateTime, default=datetime_now, nullable=False)
    context_id = Column(UnicodeText(36), nullable=False)
    progressive = Column(Integer, default=0, nullable=False)
    https = Column(Boolean, default=False, nullable=False)
    mobile = Column(Boolean, default=False, nullable=False)
    total_score = Column(Integer, default=0, nullable=False)
    expiration_date = Column(DateTime, default=datetime_never, nullable=False)
    enable_two_way_comments = Column(Boolean, default=True, nullable=False)
    enable_two_way_messages = Column(Boolean, default=True, nullable=False)
    enable_attachments = Column(Boolean, default=True, nullable=False)
    enable_whistleblower_identity = Column(Boolean, default=False, nullable=False)
    important = Column(Boolean, default=False, nullable=False)
    label = Column(UnicodeText, default='', nullable=False)
    wb_last_access = Column(DateTime, default=datetime_now, nullable=False)
    wb_access_counter = Column(Integer, default=0, nullable=False)
    status = Column(UnicodeText(36), nullable=True)
    substatus = Column(UnicodeText(36), nullable=True)
    crypto_tip_pub_key = Column(UnicodeText(56), default='', nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                UniqueConstraint('tid', 'progressive'))


class _InternalTipAnswers(Model):
    """
    This is the internal representation of Tip Questionnaire Answers
    """
    __tablename__ = 'internaltipanswers'

    internaltip_id = Column(UnicodeText(36), primary_key=True)
    questionnaire_hash = Column(UnicodeText(64), primary_key=True)
    creation_date = Column(DateTime, default=datetime_now, nullable=False)
    answers = Column(JSON, default=dict, nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['internaltip_id'], ['internaltip.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _InternalTipData(Model):
    __tablename__ = 'internaltipdata'

    internaltip_id = Column(UnicodeText(36), primary_key=True)
    key = Column(UnicodeText, primary_key=True)
    creation_date = Column(DateTime, default=datetime_now, nullable=False)
    value = Column(JSON, default=dict, nullable=False)

    @declared_attr
    def __table_args__(self):
        return (UniqueConstraint('internaltip_id', 'key'),
                ForeignKeyConstraint(['internaltip_id'], ['internaltip.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'))


class _Mail(Model):
    """
    This model keeps track of emails to be spooled by the system
    """
    __tablename__ = 'mail'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    tid = Column(Integer, default=1, nullable=False)
    creation_date = Column(DateTime, default=datetime_now, nullable=False)
    address = Column(UnicodeText, nullable=False)
    subject = Column(UnicodeText, nullable=False)
    body = Column(UnicodeText, nullable=False)

    unicode_keys = ['address', 'subject', 'body']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _Message(Model):
    """
    This table handle the direct messages between whistleblower and one
    Receiver.
    """
    __tablename__ = 'message'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    creation_date = Column(DateTime, default=datetime_now, nullable=False)
    receivertip_id = Column(UnicodeText(36), nullable=False)
    content = Column(UnicodeText, nullable=False)
    type = Column(Enum(EnumMessageType), nullable=False)
    new = Column(Boolean, default=True, nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['receivertip_id'], ['receivertip.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                CheckConstraint(self.type.in_(EnumMessageType.keys())))


class _Questionnaire(Model):
    __tablename__ = 'questionnaire'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    tid = Column(Integer, default=1, nullable=False)
    name = Column(UnicodeText, default='', nullable=False)

    unicode_keys = ['name']
    list_keys = ['steps']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _ReceiverContext(Model):
    """
    Class used to implement references between Receivers and Contexts
    """
    __tablename__ = 'receiver_context'

    context_id = Column(UnicodeText(36), primary_key=True)
    receiver_id = Column(UnicodeText(36), primary_key=True)
    order = Column(Integer, default=0, nullable=False)

    unicode_keys = ['context_id', 'receiver_id']
    int_keys = ['order']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['context_id'], ['context.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                ForeignKeyConstraint(['receiver_id'], ['user.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'))


class _ReceiverFile(Model):
    """
    This model keeps track of files destinated to a specific receiver
    """
    __tablename__ = 'receiverfile'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    internalfile_id = Column(UnicodeText(36), nullable=False)
    receivertip_id = Column(UnicodeText(36), nullable=False)
    filename = Column(UnicodeText(255), nullable=False)
    downloads = Column(Integer, default=0, nullable=False)
    last_access = Column(DateTime, default=datetime_null, nullable=False)
    new = Column(Boolean, default=True, nullable=False)
    status = Column(Enum(EnumFileStatus), default='processing', nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['internalfile_id'], ['internalfile.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                ForeignKeyConstraint(['receivertip_id'], ['receivertip.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                CheckConstraint(self.status.in_(EnumFileStatus.keys())))


class _ReceiverTip(Model):
    """
    This is the table keeping track of all the receivers activities and
    date in a Tip, Tip core data are stored in StoredTip. The data here
    provide accountability of Receiver accesses, operations, options.
    """
    __tablename__ = 'receivertip'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    internaltip_id = Column(UnicodeText(36), nullable=False)
    receiver_id = Column(UnicodeText(36), nullable=False)
    last_access = Column(DateTime, default=datetime_null, nullable=False)
    access_counter = Column(Integer, default=0, nullable=False)
    important = Column(Boolean, default=False, nullable=False)
    label = Column(UnicodeText, default='', nullable=False)
    new = Column(Boolean, default=True, nullable=False)
    enable_notifications = Column(Boolean, default=True, nullable=False)
    crypto_tip_prv_key = Column(UnicodeText(84), default='', nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['receiver_id'], ['user.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                ForeignKeyConstraint(['internaltip_id'], ['internaltip.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'))


class _Subscriber(Model):
    __tablename__ = 'subscriber'

    tid = Column(Integer, primary_key=True, nullable=False)
    subdomain = Column(UnicodeText, unique=True, nullable=False)
    language = Column(UnicodeText(12), nullable=False)
    name = Column(UnicodeText, nullable=False)
    surname = Column(UnicodeText, nullable=False)
    role = Column(UnicodeText, default='', nullable=False)
    phone = Column(UnicodeText, default='', nullable=False)
    email = Column(UnicodeText, nullable=False)
    organization_name = Column(UnicodeText, default='', nullable=False)
    organization_type = Column(UnicodeText, default='', nullable=False)
    organization_tax_code = Column(UnicodeText, default='', nullable=False)
    organization_vat_code = Column(UnicodeText, default='', nullable=False)
    organization_location1 = Column(UnicodeText, default='', nullable=False)
    organization_location2 = Column(UnicodeText, default='', nullable=False)
    organization_location3 = Column(UnicodeText, default='', nullable=False)
    organization_location4 = Column(UnicodeText, default='', nullable=False)
    organization_site = Column(UnicodeText, default='', nullable=False)
    organization_number_employees = Column(UnicodeText, default='', nullable=False)
    organization_number_users = Column(UnicodeText, default='', nullable=False)
    activation_token = Column(UnicodeText, unique=True, nullable=True)
    client_ip_address = Column(UnicodeText, nullable=False)
    client_user_agent = Column(UnicodeText, nullable=False)
    registration_date = Column(DateTime, default=datetime_now, nullable=False)
    tos1 = Column(UnicodeText, default='', nullable=False)
    tos2 = Column(UnicodeText, default='', nullable=False)

    unicode_keys = ['subdomain', 'language', 'name', 'surname', 'role', 'phone', 'email',
                    'tax_code', 'vat_code',
                    'organization_name', 'organization_type',
                    'organization_tax_code', 'organization_vat_code',
                    'organization_site',
                    'organization_location1', 'organization_location2', 'organization_location3',
                    'organization_location4',
                    'organization_number_employees', 'organization_number_users',
                    'client_ip_address', 'client_user_agent']

    bool_keys = ['tos1', 'tos2']

    optional_references = ['activation_token']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _Redirect(Model):
    """
    Class used to implement url redirects
    """
    __tablename__ = 'redirect'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    tid = Column(Integer, default=1, nullable=False)
    path1 = Column(UnicodeText, nullable=False)
    path2 = Column(UnicodeText, nullable=False)

    unicode_keys = ['path1', 'path2']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _Step(Model):
    __tablename__ = 'step'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    questionnaire_id = Column(UnicodeText(36), nullable=False)
    label = Column(JSON, default=dict, nullable=False)
    description = Column(JSON, default=dict, nullable=False)
    triggered_by_score = Column(Integer, default=0, nullable=False)
    order = Column(Integer, default=0, nullable=False)

    unicode_keys = ['questionnaire_id']
    int_keys = ['order', 'triggered_by_score']
    localized_keys = ['label', 'description']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['questionnaire_id'], ['questionnaire.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _SubmissionStatus(Model):
    """
    Contains the statuses a submission may be in
    """
    __tablename__ = 'submissionstatus'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    tid = Column(Integer, primary_key=True, default=1, nullable=False)
    label = Column(JSON, default=dict, nullable=False)
    tip_timetolive = Column(Integer, default=90, nullable=False)
    tip_timetolive_override = Column(Boolean, default=False, nullable=False)
    receivers = Column(JSON, default=list, nullable=False)
    order = Column(Integer, default=0, nullable=False)

    localized_keys = ['label']
    int_keys = ['order', 'tip_timetolive']
    bool_keys = ['tip_timetolive_override']
    json_keys = ['receivers']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _SubmissionSubStatus(Model):
    """
    Contains the substatuses that a submission may be in
    """
    __tablename__ = 'submissionsubstatus'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    tid = Column(Integer, primary_key=True, default=1, nullable=False)
    submissionstatus_id = Column(UnicodeText(36), nullable=False)
    label = Column(JSON, default=dict, nullable=False)
    tip_timetolive = Column(Integer, default=90, nullable=False)
    tip_timetolive_override = Column(Boolean, default=False, nullable=False)
    receivers = Column(JSON, default=list, nullable=False)
    order = Column(Integer, default=0, nullable=False)

    localized_keys = ['label']
    int_keys = ['order', 'tip_timetolive']
    bool_keys = ['tip_timetolive_override']
    json_keys = ['receivers']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid', 'submissionstatus_id'], ['submissionstatus.tid', 'submissionstatus.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _Tenant(Model):
    """
    Class used to implement tenants
    """
    __tablename__ = 'tenant'

    id = Column(Integer, primary_key=True, nullable=False)
    creation_date = Column(DateTime, default=datetime_now, nullable=False)
    active = Column(Boolean, default=False, nullable=False)

    bool_keys = ['active']


class _User(Model):
    """
    This model keeps track of users.
    """
    __tablename__ = 'user'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    tid = Column(Integer, default=1, nullable=False)
    creation_date = Column(DateTime, default=datetime_now, nullable=False)
    username = Column(UnicodeText, default='', nullable=False)
    salt = Column(UnicodeText(24), default='', nullable=False)
    hash_alg = Column(UnicodeText, default='ARGON2', nullable=False)
    password = Column(UnicodeText, default='', nullable=False)
    name = Column(UnicodeText, default='', nullable=False)
    description = Column(JSON, default=dict, nullable=False)
    public_name = Column(UnicodeText, default='', nullable=False)
    role = Column(Enum(EnumUserRole), default='receiver', nullable=False)
    state = Column(Enum(EnumUserState), default='enabled', nullable=False)
    last_login = Column(DateTime, default=datetime_null, nullable=False)
    mail_address = Column(UnicodeText, default='', nullable=False)
    language = Column(UnicodeText(12), nullable=False)
    password_change_needed = Column(Boolean, default=True, nullable=False)
    password_change_date = Column(DateTime, default=datetime_null, nullable=False)
    crypto_prv_key = Column(UnicodeText(84), default='', nullable=False)
    crypto_pub_key = Column(UnicodeText(56), default='', nullable=False)
    crypto_rec_key = Column(UnicodeText(80), default='', nullable=False)
    crypto_bkp_key = Column(UnicodeText(84), default='', nullable=False)
    crypto_escrow_prv_key = Column(UnicodeText(84), default='', nullable=False)
    crypto_escrow_bkp1_key = Column(UnicodeText(84), default='', nullable=False)
    crypto_escrow_bkp2_key = Column(UnicodeText(84), default='', nullable=False)
    change_email_address = Column(UnicodeText, default='', nullable=False)
    change_email_token = Column(UnicodeText, unique=True, nullable=True)
    change_email_date = Column(DateTime, default=datetime_null, nullable=False)
    reset_password_token = Column(UnicodeText, unique=True, nullable=True)
    reset_password_date = Column(UnicodeText, default=datetime_null, nullable=False)
    notification = Column(Boolean, default=True, nullable=False)
    forcefully_selected = Column(Boolean, default=False, nullable=False)
    can_delete_submission = Column(Boolean, default=False, nullable=False)
    can_postpone_expiration = Column(Boolean, default=False, nullable=False)
    can_edit_general_settings = Column(Boolean, default=False, nullable=False)
    readonly = Column(Boolean, default=False, nullable=False)
    two_factor_enable = Column(Boolean, default=False, nullable=False)
    two_factor_secret = Column(UnicodeText(32), default='', nullable=False)
    reminder_date = Column(DateTime, default=datetime_null, nullable=False)

    # BEGIN of PGP key fields
    pgp_key_fingerprint = Column(UnicodeText, default='', nullable=False)
    pgp_key_public = Column(UnicodeText, default='', nullable=False)
    pgp_key_expiration = Column(DateTime, default=datetime_null, nullable=False)
    # END of PGP key fields

    clicked_recovery_key = Column(Boolean, default=False, nullable=False)

    unicode_keys = ['username', 'role', 'state',
                    'language', 'mail_address',
                    'name', 'public_name',
                    'language', 'change_email_address',
                    'salt',
                    'two_factor_secret']

    localized_keys = ['description']

    bool_keys = ['password_change_needed',
                 'notification',
                 'can_edit_general_settings',
                 'can_delete_submission',
                 'can_postpone_expiration',
                 'two_factor_enable',
                 'forcefully_selected',
                 'readonly',
                 'clicked_recovery_key']

    date_keys = ['creation_date', 'reminder_date', 'last_login', 'password_change_date', 'pgp_key_expiration']

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                UniqueConstraint('tid', 'username'),
                CheckConstraint(self.role.in_(EnumUserRole.keys())),
                CheckConstraint(self.state.in_(EnumUserState.keys())))


class _WhistleblowerFile(Model):
    """
    This models stores metadata of files uploaded by recipients intended to be
    delivered to the whistleblower. This file is not encrypted and nor is it
    integrity checked in any meaningful way.
    """
    __tablename__ = 'whistleblowerfile'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    receivertip_id = Column(UnicodeText(36), nullable=False)
    name = Column(UnicodeText, nullable=False)
    filename = Column(UnicodeText(255), unique=True, nullable=False)
    size = Column(Integer, nullable=False)
    content_type = Column(UnicodeText, nullable=False)
    downloads = Column(Integer, default=0, nullable=False)
    creation_date = Column(DateTime, default=datetime_now, nullable=False)
    last_access = Column(DateTime, default=datetime_null, nullable=False)
    description = Column(UnicodeText, nullable=False)
    new = Column(Boolean, default=True, nullable=False)

    @declared_attr
    def __table_args__(self):
        return (ForeignKeyConstraint(['receivertip_id'], ['receivertip.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),)


class _WhistleblowerTip(Model):
    __tablename__ = 'whistleblowertip'

    id = Column(UnicodeText(36), primary_key=True, default=uuid4)
    tid = Column(Integer, default=1, nullable=False)
    receipt_hash = Column(UnicodeText(128), nullable=False)
    hash_alg = Column(UnicodeText, default='ARGON2', nullable=False)
    crypto_prv_key = Column(UnicodeText(84), default='', nullable=False)
    crypto_pub_key = Column(UnicodeText(56), default='', nullable=False)
    crypto_tip_prv_key = Column(UnicodeText(84), default='', nullable=False)

    @declared_attr
    def __table_args__(self):
        return (UniqueConstraint('tid', 'receipt_hash'),
                ForeignKeyConstraint(['id'], ['internaltip.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'),
                ForeignKeyConstraint(['tid'], ['tenant.id'], ondelete='CASCADE', deferrable=True, initially='DEFERRED'))


class ArchivedSchema(_ArchivedSchema, Base):
    pass


class AuditLog(_AuditLog, Base):
    pass


class Comment(_Comment, Base):
    pass


class Config(_Config, Base):
    pass


class ConfigL10N(_ConfigL10N, Base):
    pass


class Context(_Context, Base):
    pass


class CustomTexts(_CustomTexts, Base):
    pass


class EnabledLanguage(_EnabledLanguage, Base):
    pass


class Field(_Field, Base):
    pass


class FieldAttr(_FieldAttr, Base):
    pass


class FieldOption(_FieldOption, Base):
    pass


class FieldOptionTriggerField(_FieldOptionTriggerField, Base):
    pass


class FieldOptionTriggerStep(_FieldOptionTriggerStep, Base):
    pass


class File(_File, Base):
    pass


class IdentityAccessRequest(_IdentityAccessRequest, Base):
    pass


class InternalFile(_InternalFile, Base):
    pass


class InternalTip(_InternalTip, Base):
    pass


class InternalTipAnswers(_InternalTipAnswers, Base):
    pass


class InternalTipData(_InternalTipData, Base):
    pass


class Mail(_Mail, Base):
    pass


class Message(_Message, Base):
    pass


class Questionnaire(_Questionnaire, Base):
    pass


class ReceiverContext(_ReceiverContext, Base):
    pass


class ReceiverFile(_ReceiverFile, Base):
    pass


class ReceiverTip(_ReceiverTip, Base):
    pass


class Redirect(_Redirect, Base):
    pass


class Subscriber(_Subscriber, Base):
    pass


class SubmissionStatus(_SubmissionStatus, Base):
    pass


class SubmissionSubStatus(_SubmissionSubStatus, Base):
    pass


class Step(_Step, Base):
    pass


class Tenant(_Tenant, Base):
    pass


class User(_User, Base):
    pass


class WhistleblowerFile(_WhistleblowerFile, Base):
    pass


class WhistleblowerTip(_WhistleblowerTip, Base):
    pass
