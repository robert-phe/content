import pytest
import requests_mock
from CommonServerPython import *
from MicrosoftCloudAppSecurity import Client


RETURN_ERROR_TARGET = 'GetListRow.return_error'


@pytest.mark.parametrize(
    "severity, expected",
    [
        ("Low", 0),
        ("Medium", 1),
        ("High", 2),
    ]
)
def test_convert_severity(severity, expected):
    from MicrosoftCloudAppSecurity import convert_severity
    res = convert_severity(severity)
    assert res == expected


@pytest.mark.parametrize(
    "resolution_status, expected",
    [
        ("Open", 0),
        ("Dismissed", 1),
        ("Resolved", 2)
    ]
)
def test_convert_resolution_status(resolution_status, expected):
    from MicrosoftCloudAppSecurity import convert_resolution_status
    res = convert_resolution_status(resolution_status)
    assert res == expected


@pytest.mark.parametrize(
    "source, expected",
    [
        ("Access_control", 0),
        ("Session_control", 1),
        ("App_connector", 2),
        ("App_connector_analysis", 3),
        ("Discovery", 5),
        ("MDATP", 6)
    ]
)
def test_convert_source_type(source, expected):
    from MicrosoftCloudAppSecurity import convert_source_type
    res = convert_source_type(source)
    assert res == expected


@pytest.mark.parametrize(
    "file_type, expected",
    [
        ("Other", 0),
        ("Document", 1),
        ("Spreadsheet", 2),
        ("Presentation", 3),
        ("Text", 4),
        ("Image", 5),
        ("Folder", 6)

    ]
)
def test_convert_file_type(file_type, expected):
    from MicrosoftCloudAppSecurity import convert_file_type
    res = convert_file_type(file_type)
    assert res == expected


@pytest.mark.parametrize(
    "file_sharing, expected",
    [
        ("Private", 0),
        ("Internal", 1),
        ("External", 2),
        ("Public", 3),
        ("Public_Internet", 4)
    ]
)
def test_convert_file_sharing(file_sharing, expected):
    from MicrosoftCloudAppSecurity import convert_file_sharing
    res = convert_file_sharing(file_sharing)
    assert res == expected


@pytest.mark.parametrize(
    "ip_category, expected",
    [
        ("Corporate", 1),
        ("Administrative", 2),
        ("Risky", 3),
        ("VPN", 4),
        ("Cloud_provider", 5),
        ("Other", 6)
    ]
)
def test_convert_ip_category(ip_category, expected):
    from MicrosoftCloudAppSecurity import convert_ip_category
    res = convert_ip_category(ip_category)
    assert res == expected


@pytest.mark.parametrize(
    "is_external, expected",
    [
        ("External", True),
        ("Internal", False),
        ("No_value", None)
    ]
)
def test_convert_is_external(is_external, expected):
    from MicrosoftCloudAppSecurity import convert_is_external
    res = convert_is_external(is_external)
    assert res == expected


@pytest.mark.parametrize(
    "status, expected",
    [
        ("N/A", 0),
        ("Staged", 1),
        ("Active", 2),
        ("Suspended", 3),
        ("Deleted", 4)
    ]
)
def test_convert_status(status, expected):
    from MicrosoftCloudAppSecurity import convert_status
    res = convert_status(status)
    assert res == expected


@pytest.mark.parametrize(
    "string, expected",
    [
        ("True", True),
        ("False", False),
    ]
)
def test_str_to_bool(string, expected):
    from MicrosoftCloudAppSecurity import str_to_bool
    res = str_to_bool(string)
    assert res == expected


@pytest.mark.parametrize(
    "arg, expected",
    [
        ("3256754321", 3256754321),
        ("2020-03-20T14:28:23.382748", 1584707303),
        (2323248648.123, 2323248648)
    ]
)
def test_arg_to_timestamp(arg, expected):
    from MicrosoftCloudAppSecurity import arg_to_timestamp
    res = arg_to_timestamp(arg)
    assert res == expected


expected = {'filters': {'entity.service': {'eq': 111}, 'entity.instance': {'eq': 111}, 'severity': {'eq': 0},
                        'resolutionStatus': {'eq': 0}, 'entity.entity': {'eq':
                        {'id': '3fa9f28b-eb0e-463a-ba7b-8089fe9991e2', 'saas': 11161, 'inst': 0}}}, 'skip': 5,
            'limit': 10}
request_data = {"service": "111", "instance": "111", "severity": "Low", "resolution_status": "Open", "username":
                '{"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}', "skip": "5", "limit": "10"}


@pytest.mark.parametrize(
    "all_params, expected",
    [
        (request_data, expected)
    ]
)
def test_args_to_json_filter_list_alert(all_params, expected):
    from MicrosoftCloudAppSecurity import args_to_json_filter_list_alert
    res = args_to_json_filter_list_alert(all_params)
    assert res == expected


expected = {'filters': {'service': {'eq': 111}, 'instance': {'eq': 111}, 'ip.address': {'eq': '8.8.8.8'},
                        'ip.category': {'eq': 1}, 'user.username': {'eq': 'dev@demistodev.onmicrosoft.com'},
                        'activity.takenAction': {'eq': 'block'}, 'source': {'eq': 0}}, 'skip': 5, 'limit': 10}
request_data = {"service": "111", "instance": "111", "ip": "8.8.8.8", "ip_category": "Corporate", "username":
                'dev@demistodev.onmicrosoft.com', 'taken_action': 'block', 'source': 'Access_control',
                "skip": "5", "limit": "10"}


@pytest.mark.parametrize(
    "all_params, expected",
    [
        (request_data, expected)
    ]
)
def test_args_to_json_filter_list_activity(all_params, expected):
    from MicrosoftCloudAppSecurity import args_to_json_filter_list_activity
    res = args_to_json_filter_list_activity(all_params)
    assert res == expected


expected = {'filters': {'service': {'eq': 111}, 'instance': {'eq': 111}, 'fileType': {'eq': 0},
                        'quarantined': {'eq': True}, 'owner.entity':
                        {'eq': {"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}},
                        'sharing': {'eq': 0}, 'extension': {'eq': 'png'}, }, 'skip': 5, 'limit': 10}
request_data = {"service": "111", "instance": "111", "file_type": "Other", "owner":
                '{"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}', "sharing": 'Private',
                'extension': 'png', 'quarantined': 'True', "skip": "5", "limit": "10"}


@pytest.mark.parametrize(
    "all_params, expected",
    [
        (request_data, expected)
    ]
)
def test_args_to_json_filter_list_files(all_params, expected):
    from MicrosoftCloudAppSecurity import args_to_json_filter_list_files
    res = args_to_json_filter_list_files(all_params)
    assert res == expected


expected = {'filters': {'app': {'eq': 111}, 'instance': {'eq': 111}, 'type': {'eq': 'user'},
                        'isExternal': {'eq': True}, 'status': {'eq': 0}, 'entity':
                        {'eq': {"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}},
                        'userGroups': {'eq': '1234'}, 'isAdmin': {'eq': 'demisto'}, }, 'skip': 5, 'limit': 10}
request_data = {"app": "111", "instance": "111", "type": "user", "status": 'N/A', "username":
                '{"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}', "group_id": '1234',
                'is_admin': 'demisto', 'is_external': 'External', "skip": "5", "limit": "10"}


@pytest.mark.parametrize(
    "all_params, expected",
    [
        (request_data, expected)
    ]
)
def test_args_to_json_filter_list_users_accounts(all_params, expected):
    from MicrosoftCloudAppSecurity import args_to_json_filter_list_users_accounts
    res = args_to_json_filter_list_users_accounts(all_params)
    assert res == expected


@pytest.mark.parametrize(
    "alert_ids, customer_filters, comment, expected",
    [
        ("5f06d71dba4,289d0602ba5ac", '', '', {'filters': {'id': {'eq': ['5f06d71dba4', '289d0602ba5ac']}}}),
        ("5f06d71dba4", '', 'Irrelevant', {"comment": "Irrelevant", 'filters': {'id': {'eq': ['5f06d71dba4']}}}),
        ("", '{"filters": {"id": {"eq": ["5f06d71dba4"]}}}', "", {'filters': {'id': {'eq': ['5f06d71dba4']}}})
    ]
)
def test_args_to_json_dismiss_and_resolve_alerts(alert_ids, customer_filters, comment, expected):
    from MicrosoftCloudAppSecurity import args_to_json_dismiss_and_resolve_alerts
    res = args_to_json_dismiss_and_resolve_alerts(alert_ids, customer_filters, comment)
    assert res == expected


expected = {'entity.service': {'eq': 111}, 'entity.instance': {'eq': 111}, 'severity': {'eq': 0},
            'resolutionStatus': {'eq': 0}}
request_data = {"service": "111", "instance": "111", "severity": "Low", "resolution_status": "Open"}


@pytest.mark.parametrize(
    "all_params, expected",
    [
        (request_data, expected)
    ]
)
def test_params_to_filter(all_params, expected):
    from MicrosoftCloudAppSecurity import params_to_filter
    res = params_to_filter(all_params)
    assert res == expected


client_mocker = Client(base_url='https://demistodev.eu2.portal.cloudappsecurity.com/api/v1')


def test_alerts_list_command(requests_mock):
    from MicrosoftCloudAppSecurity import alerts_list_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/5f06d71dba4289d0602ba5ac',
                      json=ALERT_BY_ID_DATA)
    res = alerts_list_command(client_mocker, {'alert_id': '5f06d71dba4289d0602ba5ac'})
    context = res.to_context().get('EntryContext')
    assert context.get('MicrosoftCloudAppSecurity.Alert(val.alert_id == obj.alert_id)') == ALERT_BY_ID_DATA


def test_alert_dismiss_bulk_command(requests_mock):
    from MicrosoftCloudAppSecurity import alert_dismiss_bulk_command
    requests_mock.post('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/dismiss_bulk/',
                       json=DISMISSED_BY_ID_DATA)
    res = alert_dismiss_bulk_command(client_mocker, {'alert_ids': '5f06d71dba4289d0602ba5ac'})
    context = res.to_context().get('EntryContext')
    assert context.get('MicrosoftCloudAppSecurity.AlertDismiss(val.alert_ids == obj.alert_ids)') == DISMISSED_BY_ID_DATA


def test_alert_resolve_bulk_command(requests_mock):
    from MicrosoftCloudAppSecurity import alert_resolve_bulk_command
    requests_mock.post('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/resolve/',
                       json=RESOLVED_BY_ID_DATA)
    res = alert_resolve_bulk_command(client_mocker, {'alert_ids': '5f06d71dba4289d0602ba5ac'})
    context = res.to_context().get('EntryContext')
    assert context.get('MicrosoftCloudAppSecurity.AlertResolve(val.alert_ids == obj.alert_ids)') == RESOLVED_BY_ID_DATA


def test_activities_list_command(requests_mock):
    from MicrosoftCloudAppSecurity import activities_list_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/activities/'
                      '97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7',
                      json=ACTIVITIES_BY_ID_DATA)
    res = activities_list_command(client_mocker, {'activity_id': '97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7'})
    context = res.to_context().get('EntryContext')
    assert ACTIVITIES_BY_ID_DATA == context.get('MicrosoftCloudAppSecurity.Activities'
                                                '(val.activity_id == obj.activity_id)')


def test_files_list_command(requests_mock):
    from MicrosoftCloudAppSecurity import files_list_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/files/5f077ebfc3b664209dae1f6b',
                      json=FILES_BY_ID_DATA)
    res = files_list_command(client_mocker, {'file_id': '5f077ebfc3b664209dae1f6b'})
    context = res.to_context().get('EntryContext')
    assert context.get('MicrosoftCloudAppSecurity.Files(val.file_id == obj.file_id)') == FILES_BY_ID_DATA


def test_users_accounts_list_command(requests_mock):
    from MicrosoftCloudAppSecurity import users_accounts_list_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/entities/',
                      json=ENTITIES_BY_USERNAME_DATA)
    res = users_accounts_list_command(client_mocker,
                                      {'username': '{ "id": "7e14f6a3-185d-49e3-85e8-40a33d90dc90",'
                                                   ' "saas": 11161, "inst": 0 }'})
    context = res.to_context().get('EntryContext')
    assert ENTITIES_BY_USERNAME_DATA == context.get('MicrosoftCloudAppSecurity.UsersAccounts'
                                                    '(val.username == obj.username)')


ALERT_BY_ID_DATA = {
    "_id": "5f06d71dba4289d0602ba5ac",
    "timestamp": 1594283802753,
    "entities": [
        {
            "id": "5f01dce13de79160fbec4150",
            "label": "block png files",
            "policyType": "FILE",
            "type": "policyRule"
        },
        {
            "id": 15600,
            "label": "Microsoft OneDrive for Business",
            "type": "service"
        },
        {
            "id": "d10230e2-52db-4ec8-815b-c5484524d078|501f6179-e6f9-457c-9892-1590dee07ede",
            "label": "image (2).png",
            "type": "file"
        },
        {
            "em": "dev@demistodev.onmicrosoft.com",
            "entityType": 2,
            "id": "2827c1e7-edb6-4529-b50d-25984e968637",
            "inst": 0,
            "label": "demisto dev",
            "pa": "dev@demistodev.onmicrosoft.com",
            "saas": 11161,
            "type": "account"
        },
        {
            "id": "dev@demistodev.onmicrosoft.com",
            "label": "dev@demistodev.onmicrosoft.com",
            "type": "user"
        }
    ],
    "title": "block png files",
    "description": "File policy 'block png files' was matched by 'image (2).png'",
    "stories": [
        0
    ],
    "policy": {
        "id": "5f01dce13de79160fbec4150",
        "label": "block png files",
        "policyType": "FILE",
        "type": "policyRule"
    },
    "contextId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
    "threatScore": 19,
    "isSystemAlert": False,
    "idValue": 15728642,
    "statusValue": 1,
    "severityValue": 0,
    "handledByUser": 'null',
    "comment": 'null',
    "resolveTime": "2020-07-12T07:48:40.975Z",
    "URL": "https://demistodev.portal.cloudappsecurity.com/#/alerts/5f06d71dba4289d0602ba5ac"
}

ACTIVITIES_BY_ID_DATA = {
    "_id": "97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7",
    "tenantId": 97134000,
    "aadTenantId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
    "appId": 15600,
    "saasId": 15600,
    "timestamp": 1595096313000,
    "timestampRaw": 1595096313000,
    "instantiation": 1595096584556,
    "instantiationRaw": 1595096584556,
    "created": 1595096586840,
    "createdRaw": 1595096586840,
    "eventType": 233580,
    "eventTypeValue": "EVENT_O365_ONEDRIVE_GENERIC",
    "eventRouting": {
        "scubaUnpacker": False,
        "lograbber": True,
        "auditing": True
    },
    "device": {
        "clientIP": "82.166.99.178",
        "userAgent": "OneDriveMpc-Transform_Thumbnail/1.0",
        "countryCode": "IL"
    },
    "location": {
        "countryCode": "IL",
        "city": "Tel Aviv",
        "regionCode": "TA",
        "region": "Tel Aviv",
        "longitude": 34.7604,
        "latitude": 32.0679,
        "organizationSearchable": "Cellcom Group",
        "anonymousProxy": False,
        "isSatelliteProvider": False,
        "category": 0,
        "categoryValue": "NONE"
    },
    "user": {
        "userName": "avishai@demistodev.onmicrosoft.com",
        "userTags": [
            "5f01dbbc68df27c17aa6ca81"
        ]
    },
    "userAgent": {
        "family": "MICROSOFT_ONEDRIVE_FOR_BUSINESS",
        "name": "Microsoft OneDrive for Business",
        "operatingSystem": {
            "name": "Unknown",
            "family": "Unknown"
        },
        "type": "Application",
        "typeName": "Application",
        "deviceType": "OTHER",
        "nativeBrowser": True,
        "tags": [
            "000000000000000000000000"
        ],
        "os": "OTHER",
        "browser": "MICROSOFT_ONEDRIVE_FOR_BUSINESS"
    },
    "internals": {
        "otherIPs": [
            "82.166.99.178"
        ]
    },
    "mainInfo": {
        "eventObjects": [
            {
                "objType": 1,
                "role": 3,
                "tags": [],
                "name": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/",
                "id": "cac4b654-5fcf-44f0-818e-479cf8ae42ac",
                "serviceObjectType": "OneDrive Site Collection"
            },
            {
                "objType": 21,
                "role": 4,
                "tags": [],
                "name": "Avishai Brandeis",
                "instanceId": 0,
                "resolved": True,
                "saasId": 11161,
                "id": "avishai@demistodev.onmicrosoft.com",
                "link": -162371649
            },
            {
                "objType": 23,
                "role": 4,
                "tags": [
                    "5f01dbbc68df27c17aa6ca81"
                ],
                "name": "Avishai Brandeis",
                "instanceId": 0,
                "resolved": True,
                "saasId": 11161,
                "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                "link": -162371649
            }
        ],
        "rawOperationName": "FilePreviewed",
        "prettyOperationName": "FilePreviewed",
        "type": "basic"
    },
    "confidenceLevel": 20,
    "source": 2,
    "lograbberService": {
        "o365EventGrabber": True,
        "gediEvent": True
    },
    "srcAppId": 11161,
    "collected": {
        "o365": {
            "blobCreated": "2020-07-18T18:21:10.6170000Z",
            "blobId": "20200718182019454009710$20200718182110617003525$audit_sharepoint$Audit_SharePoint$emea0029"
        }
    },
    "rawDataJson": {
        "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
        "CreationTime": "2020-07-18T18:18:33.0000000Z",
        "RecordType": 6,
        "Operation": "FilePreviewed",
        "UserType": 0,
        "Workload": "OneDrive",
        "ClientIP": "82.166.99.178",
        "UserKey": "i:0h.f|membership|100300009abc2878@live.com",
        "Version": 1,
        "ObjectId": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/Documents/iban example.docx",
        "CorrelationId": "3055679f-0048-2000-2b2a-29e5b1098433",
        "UserId": "avishai@demistodev.onmicrosoft.com",
        "ListItemUniqueId": "141133f2-6710-4f65-9c3b-c840a8d71483",
        "EventSource": "SharePoint",
        "SourceFileExtension": "docx",
        "UserAgent": "OneDriveMpc-Transform_Thumbnail/1.0",
        "SourceRelativeUrl": "Documents",
        "ItemType": "File",
        "SourceFileName": "iban example.docx",
        "Id": "97ee2049-893e-4c9d-a312-08d82b46faf7",
        "ApplicationId": "4345a7b9-9a63-4910-a426-35363201d503",
        "ListId": "0d2a8402-c671-43cd-b8ec-b49882d43e08",
        "WebId": "8a6420f5-3cde-4d37-911c-ce86af6d3910",
        "SiteUrl": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/",
        "Site": "cac4b654-5fcf-44f0-818e-479cf8ae42ac",
        "DoNotDistributeEvent": True
    },
    "resolvedActor": {
        "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
        "saasId": "11161",
        "instanceId": "0",
        "tags": [
            "5f01dbbc68df27c17aa6ca81"
        ],
        "objType": "23",
        "name": "Avishai Brandeis",
        "role": "4",
        "resolved": True
    },
    "uid": "97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7",
    "appName": "Microsoft OneDrive for Business",
    "eventTypeName": "EVENT_CATEGORY_UNSPECIFIED",
    "classifications": [],
    "entityData": {
        "0": {
            "displayName": "Avishai Brandeis",
            "id": {
                "id": "avishai@demistodev.onmicrosoft.com",
                "saas": 11161,
                "inst": 0
            },
            "resolved": True
        },
        "1": None,
        "2": {
            "displayName": "Avishai Brandeis",
            "id": {
                "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                "saas": 11161,
                "inst": 0
            },
            "resolved": True
        }
    },
    "description_id": "EVENT_DESCRIPTION_BASIC_EVENT",
    "description_metadata": {
        "target_object": "",
        "operation_name": "FilePreviewed",
        "colon": "",
        "dash": ""
    },
    "description": "FilePreviewed",
    "genericEventType": "ENUM_ACTIVITY_GENERIC_TYPE_BASIC",
    "severity": "INFO"
}

FILES_BY_ID_DATA = {
    "_id": "5f077ebfc3b664209dae1f6b",
    "_tid": 97134000,
    "appId": 15600,
    "id": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|56aa5551-0c4c-42d7-93f1-57ccdca766aa",
    "saasId": 15600,
    "instId": 0,
    "fileSize": 149,
    "createdDate": 1594326579000,
    "modifiedDate": 1594326594000,
    "driveId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
    "scanVersion": 4,
    "parentId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b",
    "alternateLink": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/Documents/20200325_104025.jpg.txt",
    "isFolder": False,
    "fileType": [
        4,
        "TEXT"
    ],
    "name": "20200325_104025.jpg.txt",
    "isForeign": False,
    "noGovernance": False,
    "fileAccessLevel": [
        0,
        "PRIVATE"
    ],
    "ownerAddress": "avishai@demistodev.onmicrosoft.com",
    "externalShares": [],
    "emails": [
        "avishai@demistodev.onmicrosoft.com"
    ],
    "groupIds": [],
    "groups": [],
    "domains": [
        "demistodev.onmicrosoft.com"
    ],
    "mimeType": "text/plain",
    "parentIds": [
        "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
    ],
    "ownerExternal": False,
    "fileExtension": "txt",
    "lastNrtTimestamp": 1594326781863,
    "effectiveParents": [
        "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
        "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
    ],
    "collaborators": [],
    "sharepointItem": {
        "UniqueId": "56aa5551-0c4c-42d7-93f1-57ccdca766aa",
        "ServerRelativeUrl": "/personal/avishai_demistodev_onmicrosoft_com/Documents/20200325_104025.jpg.txt",
        "Name": "20200325_104025.jpg.txt",
        "Length": 149,
        "TimeLastModified": "2020-07-09T20:29:54Z",
        "TimeCreated": "2020-07-09T20:29:39Z",
        "Author": {
            "sourceBitmask": 0,
            "oneDriveEmail": "avishai@demistodev.onmicrosoft.com",
            "trueEmail": "avishai@demistodev.onmicrosoft.com",
            "externalUser": False,
            "LoginName": "i:0#.f|membership|avishai@demistodev.onmicrosoft.com",
            "name": "Avishai Brandeis",
            "idInSiteCollection": "4",
            "sipAddress": "avishai@demistodev.onmicrosoft.com",
            "Email": "avishai@demistodev.onmicrosoft.com",
            "Title": "Avishai Brandeis"
        },
        "LinkingUrl": "",
        "parentUniqueId": "8f83a489-34b7-4bb6-a331-260d1291ef6b",
        "roleAssignments": [],
        "hasUniqueRoleAssignments": False,
        "urlFromMetadata": None,
        "ModifiedBy": {
            "LoginName": "i:0#.f|membership|tmcassp_fa02d7a6fe55edb22020060112572594@demistodev.onmicrosoft.com",
            "Title": "Cloud App Security Service Account for SharePoint",
            "Email": ""
        },
        "scopeId": "D853886D-DDEE-4A5D-BCB9-B6F072BC1413",
        "isFolder": False,
        "encodedAbsUrl": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/Documents/20200325_104025.jpg.txt"
    },
    "siteCollection": "/personal/avishai_demistodev_onmicrosoft_com",
    "sitePath": "/personal/avishai_demistodev_onmicrosoft_com",
    "filePath": "/personal/avishai_demistodev_onmicrosoft_com/Documents/20200325_104025.jpg.txt",
    "spDomain": "https://demistodev-my.sharepoint.com",
    "siteCollectionId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac",
    "ftype": 4,
    "facl": 0,
    "fstat": 0,
    "unseenScans": 0,
    "fileStatus": [
        0,
        "EXISTS"
    ],
    "name_l": "20200325_104025.jpg.txt",
    "snapshotLastModifiedDate": "2020-07-09T22:15:39.820Z",
    "ownerName": "Avishai Brandeis",
    "originalId": "5f077ebfc3b664209dae1f6b",
    "dlpScanResults": [],
    "fTags": [],
    "enriched": True,
    "display_collaborators": [],
    "appName": "Microsoft OneDrive for Business",
    "actions": [
        {
            "task_name": "QuarantineTask",
            "display_title": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_TITLE",
            "type": "file",
            "governance_type": None,
            "bulk_support": True,
            "has_icon": True,
            "display_description": {
                "template": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_DESCRIPTION",
                "parameters": {
                    "fileName": "20200325_104025.jpg.txt"
                }
            },
            "bulk_display_description": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_BULK_DISPLAY_DESCRIPTION",
            "preview_only": False,
            "display_alert_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_TEXT",
            "display_alert_success_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_SUCCESS_TEXT",
            "is_blocking": None,
            "confirm_button_style": "red",
            "optional_notify": None,
            "uiGovernanceCategory": 1,
            "alert_display_title": None,
            "confirmation_button_text": None,
            "confirmation_link": None
        },
        {
            "task_name": "RescanFileTask",
            "display_title": "TASKS_ADALIBPY_RESCAN_FILE_DISPLAY_TITLE",
            "type": "file",
            "governance_type": None,
            "bulk_support": True,
            "has_icon": True,
            "display_description": None,
            "bulk_display_description": None,
            "preview_only": False,
            "display_alert_text": None,
            "display_alert_success_text": None,
            "is_blocking": None,
            "confirm_button_style": "red",
            "optional_notify": None,
            "uiGovernanceCategory": 0,
            "alert_display_title": None,
            "confirmation_button_text": None,
            "confirmation_link": None
        },
        {
            "task_name": "TrashFileTask",
            "display_title": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_TITLE",
            "type": "file",
            "governance_type": None,
            "bulk_support": True,
            "has_icon": True,
            "display_description": {
                "template": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_DESCRIPTION",
                "parameters": {
                    "fileName": "20200325_104025.jpg.txt"
                }
            },
            "bulk_display_description": "TASKS_ADALIBPY_TRASH_FILE_BULK_DISPLAY_DESCRIPTION",
            "preview_only": False,
            "display_alert_text": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_ALERT_TEXT",
            "display_alert_success_text": "TASKS_ADALIBPY_TRASH_FILE_ALERT_SUCCESS_TEXT",
            "is_blocking": None,
            "confirm_button_style": "red",
            "optional_notify": None,
            "uiGovernanceCategory": 1,
            "alert_display_title": None,
            "confirmation_button_text": None,
            "confirmation_link": None
        }
    ],
    "fileTypeDisplay": "File"
}

ENTITIES_BY_USERNAME_DATA = {
    "data": [
        {
            "type": 1,
            "status": 2,
            "displayName": "MS Graph Groups",
            "id": "7e14f6a3-185d-49e3-85e8-40a33d90dc90",
            "_id": "5f01dc3d229037823e3b9e92",
            "userGroups": [
                {
                    "_id": "5e6fa9ade2367fc6340f487e",
                    "id": "0000003b0000000000000000",
                    "name": "Application (Cloud App Security)",
                    "description": "App-initiated",
                    "usersCount": 562
                },
                {
                    "_id": "5e6fa9ace2367fc6340f4864",
                    "id": "000000200000000000000000",
                    "name": "External users",
                    "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                    "usersCount": 106
                }
            ],
            "identifiers": [],
            "sid": None,
            "appData": {
                "appId": 11161,
                "name": "Office 365",
                "saas": 11161,
                "instance": 0
            },
            "isAdmin": False,
            "isExternal": True,
            "email": None,
            "role": None,
            "organization": None,
            "lastSeen": "2020-07-19T06:59:24Z",
            "domain": None,
            "scoreTrends": None,
            "subApps": [],
            "threatScore": None,
            "idType": 17,
            "isFake": False,
            "ii": "11161|0|7e14f6a3-185d-49e3-85e8-40a33d90dc90",
            "actions": [],
            "username": "{\"id\": \"7e14f6a3-185d-49e3-85e8-40a33d90dc90\", \"saas\": 11161, \"inst\": 0}",
            "sctime": None
        }
    ],
    "hasNext": False,
    "max": 100,
    "total": 1,
    "moreThanTotal": False
}

DISMISSED_BY_ID_DATA = {
    "dismissed": 1
}

RESOLVED_BY_ID_DATA = {
    "resolved": 1
}
