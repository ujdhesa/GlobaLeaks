# -*- coding: utf-8
#   Requests
#   ********
#
# This file contains the specification of all the requests that can be made by a
# GLClient to a GLBackend.
# These specifications may be used with rest.validateMessage() inside each of the API
# handler in order to verify if the request is correct.

import copy

from globaleaks import models
from globaleaks.models.config_desc import ConfigL10NFilters

key_regexp = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$|^[a-z_]{0,100}$'
key_regexp_or_empty = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$|^[a-z_]{0,100}$|^$'
uuid_regexp = r'^([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$'
uuid_regexp_or_empty = r'^([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$|^$'
user_role_regexp = r'^(admin|custodian|receiver)$'
user_state_regexp = r'^(enabled|disabled)$'
email_regexp = r'^(([\w+-\.]){0,100}[\w]{1,100}@([\w+-\.]){0,100}[\w]{1,100})$'
email_regexp_or_empty = r'^(([\w+-\.]){0,100}[\w]{1,100}@([\w+-\.]){0,100}[\w]{1,100})$|^$'
hostname_regexp = r'^[0-9a-z\-\.]+$'
hostname_regexp_or_empty = r'^[0-9a-z\-\.]+$|^$'
subdomain_regexp = r'^[0-9a-z\-]+$'
subdomain_regexp_or_empty = r'^[0-9a-z\-]+$|^$'
https_url_regexp = r'^https://([0-9a-z\-]+)\.(.*)$'
https_url_regexp_or_empty = r'^https://([0-9a-z\-]+)\.(.*)$|^$'
tip_operation_regexp = r'^(postpone|set)$'
short_text_regexp = r'^.{1,255}$'
languages_list_regexp = r'^([a-zA-Z-]+)?(,\s*[a-zA-Z-]+)*$'

token_regexp = r'([a-z0-9]{64})'
token_type_regexp = r'^submission$'

field_instance_regexp = (r'^('
                         'instance|'
                         'reference|'
                         'template)$')

field_type_regexp = (r'^('
                     'inputbox|'
                     'textarea|'
                     'selectbox|'
                     'multichoice|'
                     'checkbox|'
                     'tos|'
                     'fileupload|'
                     'number|'
                     'email|'
                     'date|'
                     'daterange|'
                     'fieldgroup)$')

field_attr_type_regexp = (r'^('
                          'int|'
                          'bool|'
                          'unicode|'
                          'localized)$')

identityaccessreply_regexp = (r'^('
                              'pending|'
                              'authorized|'
                              'denied)$')


def get_multilang_request_format(request_format, localized_strings):
    ret = copy.deepcopy(request_format)

    for ls in localized_strings:
        ret[ls] = dict

    return ret


DateType = r'(.*)'

# ContentType = r'(application|audio|text|video|image)'
# via stackoverflow:
# /^(application|audio|example|image|message|model|multipart|text|video)\/[a-zA-Z0-9]+([+.-][a-zA-z0-9]+)*$/
ContentType = r'(.*)'

AdminTenantDesc = {
    'name': str,
    'mode': str,
    'active': bool,
    'subdomain': subdomain_regexp_or_empty
}

FileDesc = {
    'name': str,
    'description': str,
    'size': int,
    'type': ContentType,
    'date': DateType
}

AuthDesc = {
    'tid': int,
    'username': str,
    'password': str,
    'authcode': str
}

ReceiptAuthDesc = {
    'receipt': str
}

TokenAuthDesc = {
    'authtoken': str
}

TokenAnswerDesc = {
    'answer': int
}

SubmissionDesc = {
    'context_id': uuid_regexp,
    'receivers': [uuid_regexp],
    'identity_provided': bool,
    'removed_files': list,
    'answers': dict,
    'total_score': int
}

AdminUserDesc = {
    'username': str,
    'name': str,
    'description': str,
    'public_name': str,
    'role': user_role_regexp,
    'password': str,
    'old_password': str,
    'password_change_needed': bool,
    'state': user_state_regexp,
    'mail_address': email_regexp,
    'pgp_key_remove': bool,
    'pgp_key_fingerprint': str,
    'pgp_key_expiration': str,
    'pgp_key_public': str,
    'language': str,
    'notification': bool,
    'can_edit_general_settings': bool,
    'can_delete_submission': bool,
    'can_postpone_expiration': bool,
    'forcefully_selected': bool,
    'send_account_activation_link': bool
}

UserUserDesc = {
    'username': str,
    'name': str,
    'description': str,
    'public_name': str,
    'role': user_role_regexp,
    'password': str,
    'old_password': str,
    'password_change_needed': bool,
    'mail_address': email_regexp,
    'pgp_key_remove': bool,
    'pgp_key_fingerprint': str,
    'pgp_key_expiration': str,
    'pgp_key_public': str,
    'language': str,
    'notification': bool
}

ReceiverOperationDesc = {
    'operation': str,
    'rtips': [uuid_regexp]
}

CommentDesc = {
    'content': str
}

OpsDesc = {
    'operation': str,
    'args': dict,
}

TipOpsDesc = {
    'operation': tip_operation_regexp,
    'args': dict
}

AdditionalQuestionnaireAnswers = {
    'cmd': str,
    'answers': dict
}

WhisleblowerIdentityAnswers = {
    'identity_field_id': uuid_regexp,
    'identity_field_answers': dict
}

AdminNodeDesc = {
    'name': str,
    'presentation': str,
    'footer': str,
    'disclaimer_text': str,
    'rootdomain': hostname_regexp_or_empty,
    'whistleblowing_question': str,
    'whistleblowing_button': str,
    'languages_enabled': [str],
    'languages_supported': list,
    'timezone': int,
    'default_language': str,
    'default_questionnaire': str,
    'maximum_filesize': int,
    'https_admin': bool,
    'https_custodian': bool,
    'https_whistleblower': bool,
    'https_receiver': bool,
    'https_preload': bool,
    'can_postpone_expiration': bool,
    'can_delete_submission': bool,
    'allow_indexing': bool,
    'disable_privacy_badge': bool,
    'enable_receipt_hint': bool,
    'enable_ricochet_panel': bool,
    'ricochet_address': str,
    'do_not_expose_users_names': bool,
    'disable_submissions': bool,
    'multisite_login': bool,
    'simplified_login': bool,
    'enable_custodian': bool,
    'enable_scoring_system': bool,
    'enable_signup': bool,
    'mode': str,
    'signup_tos1_enable': bool,
    'signup_tos1_title': str,
    'signup_tos1_text': str,
    'signup_tos1_checkbox_label': str,
    'signup_tos2_enable': bool,
    'signup_tos2_title': str,
    'signup_tos2_text': str,
    'signup_tos2_checkbox_label': str,
    'enable_custom_privacy_badge': bool,
    'custom_privacy_badge_text': str,
    'header_title_homepage': str,
    'contexts_clarification': str,
    'show_contexts_in_alphabetical_order': bool,
    'threshold_free_disk_megabytes_high': int,
    'threshold_free_disk_megabytes_low': int,
    'threshold_free_disk_percentage_high': int,
    'threshold_free_disk_percentage_low': int,
    'password_change_period': int,
    'unread_reminder_time': int,
    'reachable_via_web': bool,
    'anonymize_outgoing_connections': bool,
    'enable_admin_exception_notification': bool,
    'enable_developers_exception_notification': bool,
    'ip_filter_admin_enable': bool,
    'ip_filter_admin': str,
    'ip_filter_custodian_enable': bool,
    'ip_filter_custodian': str,
    'ip_filter_receiver_enable': bool,
    'ip_filter_receiver': str,
    'log_level': str,
    'enable_private_annotations': bool,
    'log_accesses_of_internal_users': bool,
    'two_factor': bool,
    'encryption': bool,
    'escrow': bool,
    'multisite': bool,
    'adminonly': bool
}

AdminNotificationDesc = {
    'smtp_server': str,
    'smtp_port': int,
    'smtp_security': str,  # 'TLS' or 'SSL' only
    'smtp_authentication': bool,
    'smtp_username': str,
    'smtp_password': str,
    'smtp_source_email': email_regexp,
    'disable_admin_notification_emails': bool,
    'disable_custodian_notification_emails': bool,
    'disable_receiver_notification_emails': bool,
    'tip_expiration_threshold': int
}

AdminNotificationDesc.update({k: str for k in ConfigL10NFilters['notification']})

AdminFieldOptionDesc = {
    'id': uuid_regexp_or_empty,
    'label': str,
    'hint1': str,
    'hint2': str,
    'block_submission': bool,
    'order': int,
    'score_type': str,
    'score_points': int,
    'trigger_receiver': list
}

AdminFieldOptionDescRaw = get_multilang_request_format(AdminFieldOptionDesc, models.FieldOption.localized_keys)

AdminFieldAttrDesc = {
    'id': uuid_regexp_or_empty,
    'name': str,
    'type': field_attr_type_regexp,
    'value': list
}

AdminFieldAttrDescRaw = get_multilang_request_format(AdminFieldAttrDesc, models.FieldAttr.localized_keys)

AdminFieldDesc = {
    'id': key_regexp_or_empty,
    'instance': field_instance_regexp,
    'template_id': key_regexp_or_empty,
    'template_override_id': key_regexp_or_empty,
    'step_id': uuid_regexp_or_empty,
    'fieldgroup_id': key_regexp_or_empty,
    'label': str,
    'description': str,
    'hint': str,
    'placeholder': str,
    'multi_entry': bool,
    'x': int,
    'y': int,
    'width': int,
    'required': bool,
    'preview': bool,
    'type': field_type_regexp,
    'attrs': dict,
    'options': [AdminFieldOptionDesc],
    'children': list,
    'triggered_by_score': int,
    'triggered_by_options': list
}

AdminFieldDescRaw = get_multilang_request_format(AdminFieldDesc, models.Field.localized_keys)
AdminFieldDescRaw['options'] = [AdminFieldOptionDescRaw]
# AdminFieldDescRaw['attrs']; FIXME: we still miss a way for validating a hierarchy where
#                                    we have a variable dictionary like the attrs dictionary.

AdminStepDesc = {
    'id': uuid_regexp_or_empty,
    'label': str,
    'description': str,
    'children': [AdminFieldDesc],
    'questionnaire_id': key_regexp_or_empty,
    'order': int,
    'triggered_by_score': int,
    'triggered_by_options': list
}

AdminStepDescRaw = get_multilang_request_format(AdminStepDesc, models.Step.localized_keys)
AdminStepDescRaw['children'] = [AdminFieldDescRaw]

AdminQuestionnaireDesc = {
    'id': key_regexp_or_empty,
    'name': str,
    'steps': list
}

AdminQuestionnaireDescRaw = get_multilang_request_format(AdminQuestionnaireDesc, models.Questionnaire.localized_keys)
AdminQuestionnaireDescRaw['steps'] = list

AdminContextDesc = {
    'id': uuid_regexp_or_empty,
    'name': str,
    'status': str,
    'description': str,
    'languages': languages_list_regexp,
    'maximum_selectable_receivers': int,
    'tip_timetolive': int,
    'receivers': [uuid_regexp],
    'select_all_receivers': bool,
    'show_recipients_details': bool,
    'allow_recipients_selection': bool,
    'enable_comments': bool,
    'enable_messages': bool,
    'enable_two_way_comments': bool,
    'enable_two_way_messages': bool,
    'enable_attachments': bool,
    'enable_rc_to_wb_files': bool,
    'score_threshold_medium': int,
    'score_threshold_high': int,
    'score_receipt_text_custom': bool,
    'score_receipt_text_l': str,
    'score_receipt_text_m': str,
    'score_receipt_text_h': str,
    'score_threshold_receipt': int,
    'order': int,
    'show_steps_navigation_interface': bool,
    'show_receivers_in_alphabetical_order': bool,
    'questionnaire_id': key_regexp_or_empty,
    'additional_questionnaire_id': key_regexp_or_empty
}

AdminTLSCertFilesConfigDesc = {
    'key': str,
    'chain': str,
    'cert': str,
}

AdminTLSCfgFileResourceDesc = {
    'name': str,
    'content': str,
}

AdminCSRFileDesc = {
    'name': short_text_regexp,
    'content': {
        'country': r'[A-Za-z]{2}',
        'province': short_text_regexp,
        'city': short_text_regexp,
        'company': short_text_regexp,
        'department': short_text_regexp,
        'email': email_regexp
    }
}

AdminRedirectDesc = {
    'path1': str,
    'path2': str
}

NodeDesc = {
    'name': str,
    'presentation': str,
    'footer': str,
    'disclaimer_text': str,
    'hostname': hostname_regexp_or_empty,
    'rootdomain': hostname_regexp_or_empty,
    'languages_enabled': [str],
    'languages_supported': list,
    'default_language': str,
    'maximum_filesize': int,
    'https_admin': bool,
    'https_custodian': bool,
    'https_whistleblower': bool,
    'https_receiver': bool,
    'can_postpone_expiration': bool,
    'can_delete_submission': bool,
    'allow_indexing': bool,
    'disable_privacy_badge': bool,
    'enable_receipt_hint': bool,
    'multisite_login': bool,
    'simplified_login': bool,
    'enable_custom_privacy_badge': bool,
    'custom_privacy_badge_text': str
}

TipOverviewDesc = {
    'id': uuid_regexp,
    'context_id': uuid_regexp,
    'creation_date': DateType,
    'expiration_date': DateType
}

TipsOverviewDesc = [TipOverviewDesc]

FileOverviewDesc = {
    'id': uuid_regexp,
    'itip': uuid_regexp,
    'path': str
}

ReceiverIdentityAccessRequestDesc = {
    'request_motivation': str
}

CustodianIdentityAccessRequestDesc = {
    'reply': identityaccessreply_regexp,
    'reply_motivation': str
}

FilesOverviewDesc = [FileOverviewDesc]

StatsDesc = {
    'file_uploaded': int,
    'new_submission': int,
    'finalized_submission': int,
    'anon_requests': int,
    'creation_date': DateType
}

StatsCollectionDesc = [StatsDesc]

AnomalyDesc = {
    'message': str,
    'creation_date': DateType
}

AnomalyCollectionDesc = [AnomalyDesc]

ReceiverDesc = {
    'name': str,
    'description': str,
    'id': uuid_regexp,
    'state': user_state_regexp,
    'can_delete_submission': bool,
    'can_postpone_expiration': bool
}

ReceiverCollectionDesc = [ReceiverDesc]

ContextDesc = {
    'id': uuid_regexp,
    'name': str,
    'status': str,
    'description': str,
    'languages': languages_list_regexp,
    'order': int,
    'receivers': [uuid_regexp],
    'select_all_receivers': bool,
    'tip_timetolive': int,
    'show_recipients_details': bool,
    'allow_recipients_selection': bool,
    'maximum_selectable_receivers': int,
    'enable_comments': bool,
    'enable_messages': bool,
    'enable_two_way_messages': bool,
    'enable_attachments': bool,
    'show_receivers_in_alphabetical_order': bool,
    'picture': bool
}

ContextCollectionDesc = [ContextDesc]

PublicResourcesDesc = {
    'node': NodeDesc,
    'contexts': [ContextDesc],
    'receivers': [ReceiverDesc]
}

InternalTipDesc = {
    'id': uuid_regexp,
    'new': bool,
    'context_id': uuid_regexp,
    'wb_steps': list,
    'receivers': [uuid_regexp],
    'files': [uuid_regexp],
    'creation_date': DateType,
    'expiration_date': DateType,
    'identity_provided': bool
}

WizardDesc = {
    'node_language': str,
    'node_name': str,
    'admin_username': str,
    'admin_name': str,
    'admin_password': str,
    'admin_mail_address': str,
    'admin_escrow': bool,
    'receiver_username': str,
    'receiver_name': str,
    'receiver_password': str,
    'receiver_mail_address': str,
    'profile': r'^(default)$',
    'skip_admin_account_creation': bool,
    'skip_recipient_account_creation': bool,
    'enable_developers_exception_notification': bool
}

SignupDesc = {
    'subdomain': subdomain_regexp,
    'name': str,
    'surname': str,
    'role': str,
    'phone': str,
    'email': str,
    'organization_name': str,
    'organization_type': str,
    'organization_tax_code': str,
    'organization_vat_code': str,
    'organization_location1': str,
    'organization_location2': str,
    'organization_location3': str,
    'organization_location4': str,
    'organization_site': str,
    'organization_number_employees': str,
    'organization_number_users': str,
    'hear_channel': str,
    'tos1': bool,
    'tos2': bool
}

SupportDesc = {
    'mail_address': str,
    'text': str
}

ExceptionDesc = {
    'errorUrl': str,
    'errorMessage': str,
    'stackTrace': list,
    'agent': str
}

PasswordReset1Desc = {
    'username': str
}

PasswordReset2Desc = {
    'reset_token': str,
    'recovery_key': str,
    'auth_code': str
}

SiteSettingsDesc = {
    'name': str,
    'header_title_homepage': str,
    'presentation': str,
    'footer': str,
    'enable_ricochet_panel': bool,
    'ricochet_address': str
}

QuestionnaireDuplicationDesc = {
    'questionnaire_id': str,
    'new_name': str
}

SubmissionStatusDesc = {
    'label': str,
    'order': int
}

SubmissionSubStatusDesc = {
    'label': str,
    'order': int
}
