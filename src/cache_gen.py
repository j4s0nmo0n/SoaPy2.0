import json
import logging
import unicodedata
from base64 import b64decode, b64encode
from uuid import UUID, uuid4 
import os
from datetime import datetime, timezone, timedelta 
import sys 

from impacket.ldap.ldaptypes import LDAP_SID, SR_SECURITY_DESCRIPTOR, ACE, ACL, ACCESS_MASK
from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, 
    ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE
)
try:
    from impacket.ldap.ldaptypes import ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
    from impacket.ldap.ldaptypes import OBJECTTYPE_GUID_MAP as IMPACKET_OBJECTTYPE_GUID_MAP
    ACCESS_ALLOWED_ACE_TYPE = 0x00 
    ACCESS_DENIED_ACE_TYPE = 0x01
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
except ImportError:
    IMPACKET_OBJECTTYPE_GUID_MAP = {} 
    ACE_OBJECT_TYPE_PRESENT = 0x1 
    ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2 
    logging.warning("impacket.ldap.ldaptypes.OBJECTTYPE_GUID_MAP or specific ACE flags not found. Extended rights name resolution will be limited.")
    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_DENIED_ACE_TYPE = 0x01
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
    
try:
    from cryptography import x509
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from src.adws import ADWSConnect, NTLMAuth 
from src.soap_templates import NAMESPACES

ADS_RIGHT_DS_CONTROL_ACCESS      = 0x00000100 
ADS_RIGHT_DS_CREATE_CHILD        = 0x00000001
ADS_RIGHT_DS_DELETE_CHILD        = 0x00000002
ADS_RIGHT_DS_LIST_CONTENTS       = 0x00000004
ADS_RIGHT_DS_SELF                = 0x00000008 
ADS_RIGHT_DS_READ_PROP           = 0x00000010
ADS_RIGHT_DS_WRITE_PROP          = 0x00000020
ADS_RIGHT_DS_DELETE_TREE         = 0x00000040
ADS_RIGHT_DS_LIST_OBJECT         = 0x00000080

BH_FULL_CONTROL_MASKS = [0x10000000, 0x000F01FF, 0x001F01FF]

KNOWN_BINARY_ADWS_ATTRIBUTES = ["objectsid", "objectguid", "ntsecuritydescriptor", "sidhistory", "cacertificate", "pkiexpirationperiod", "pkioverlapperiod", "msds-allowedtoactonbehalfofotheridentity"]
SOAPHOUND_LDAP_PROPERTIES = sorted(list(set([
    "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID",
    "primaryGroupID", "distinguishedName", "lastLogonTimestamp", "pwdLastSet", 
    "servicePrincipalName", "description", "operatingSystem", "sIDHistory",
    "nTSecurityDescriptor", "userAccountControl", "whenCreated", "lastLogon",   
    "displayName", "title", "homeDirectory", 
    "scriptPath", "adminCount", "member", "memberOf", "msDS-Behavior-Version", 
    "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "gPCFileSysPath", "gPLink", "gPOptions", "objectClass", 
    "trustAttributes", "trustDirection", "trustPartner", "flatName", "securityIdentifier", 
    "instanceType", "whenChanged", "uSNChanged", "mail",
    "ms-MCS-AdmPwdExpirationTime", 
])))
PKI_CERTDUMP_PROPERTIES = sorted(list(set([
    "name", "displayName", "distinguishedName", "objectGUID", "objectClass", "cn",
    "nTSecurityDescriptor", "dNSHostName", "certificateTemplates", "cACertificate", 
    "flags", "msPKI-Minimal-Key-Size", "msPKI-Certificate-Name-Flag", 
    "msPKI-Enrollment-Flag", "msPKI-Private-Key-Flag", 
    "pKIExtendedKeyUsage", "pKIExpirationPeriod", "pKIOverlapPeriod",
    "msPKI-Cert-Template-OID", "revision", "pKIKeyUsage", "msPKI-RA-Signature",
    "msPKI-RA-Application-Policies", "msPKI-Certificate-Application-Policy", 
])))
SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT = { 
    "user": 0, "computer": 1, "group": 2, "grouppolicycontainer": 3,
    "domaindns": 4, "domain": 4, "organizationalunit": 5, 
    "container": 6, "rpccontainer": 6, 
    "builtindomain": 7, "foreignsecurityprincipal": 2, "trusteddomain": 4,
    "certificationauthority": 8, "pkienrollmentservice": 8, 
    "pkicertificatetemplate": 9, 
}
BH_TYPE_LABEL_MAP = {
    0: "User", 1: "Computer", 2: "Group", 3: "Gpo",
    4: "Domain", 5: "OU", 6: "Container", 7: "Domain", 
    8: "CA", 9: "CertTemplate",
}
SOAPHOUND_OBJECT_CLASS_PRIORITY = [ 
    "computer", "user", "group", "foreignsecurityprincipal", "grouppolicycontainer",
    "pkicertificatetemplate", "certificationauthority", "pkienrollmentservice",
    "organizationalunit", "domaindns", "domain", "trusteddomain",
    "container", "rpccontainer", "builtindomain"
]

# GUID Mappings - Nommé BH_EXTRIGHTS_GUID_MAPPING pour correspondre à l'usage dans _parse_aces
BH_EXTRIGHTS_GUID_MAPPING = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword", "ab721a53-1e2f-11d0-9819-00aa0040529b": "AllExtendedRights", 
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "GetChanges", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "GetChangesAll",      
    "89e95b76-444d-4c62-991a-0facbeda640c": "GetChangesInFilteredSet", "bf9679c0-0de6-11d0-a285-00aa003049e2": "WriteMember", 
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "AllowedToAct", "f3a64788-5306-11d1-a9c5-0000f80367c1": "WriteSPN", 
    "4c164200-20c0-11d0-a768-00aa006e0529": "WriteAccountRestrictions", "5b47d60f-6090-40b2-9f37-2a4de88f3063": "AddKeyCredentialLink", 
    "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "SendAs", "e45795b2-9455-11d1-aebd-0000f80367c1": "WriteDnsHostname",
    "f30e3bbf-9ff0-11d1-b603-0000f80367c1": "WriteGPLink", "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll", 
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "AutoEnroll", "46a9b27d-abc7-4487-8913-871205081a51": "ManageCA", 
    "06023111-9f53-40a8-a3e5-44ace4003404": "ManageCertificates", "9923a32a-3607-11d2-b9be-0000f87a36b2": "ValidatedSPN",
    "771727b1-31b8-4cdf-ae62-4fe39fadf89e": "ValidatedDnsHostname", "00000000-0000-0000-0000-000000000000": "All", 
    "16736335-0a42-4831-8546-de7302805e3a": "ReadLAPSPassword", "bf967aba-0de6-11d0-a285-00aa003049e2": "UserClassGuid", 
    "bf967a9c-0de6-11d0-a285-00aa003049e2": "GroupClassGuid", "bf967a86-0de6-11d0-a285-00aa003049e2": "ComputerClassGuid",
    "c7407360-20bf-11d0-a768-00aa006e0529": "ms-MCS-AdmPwdGuid", 
    "12106da6-44a8-4508-8158-3722f124673f": "msLAPS-PasswordGuid",
}
# Liste des noms de droits étendus que BloodHound.py considère "intéressants" pour le mapping
INTERESTING_BH_GUID_RIGHTS_NAMES = [
    "ForceChangePassword", "WriteMember", "AllowedToAct", "WriteSPN", 
    "WriteAccountRestrictions", "AddKeyCredentialLink", "SendAs", 
    "WriteDnsHostname", "WriteGPLink", "Enroll", "AutoEnroll", 
    "ManageCA", "ManageCertificates", "ValidatedSPN", 
    "ValidatedDnsHostname", "ReadLAPSPassword",
    # AllExtendedRights est traité séparément
]

MSPKI_CERTIFICATE_NAME_FLAG_MAP = {0x1: "ENROLLEE_SUPPLIES_SUBJECT", 0x2: "SUBJECT_ALT_REQUIRE_DOMAIN_DNS", 0x10000: "SUBJECT_REQUIRE_DNS_AS_CN", 0x20000: "SUBJECT_REQUIRE_EMAIL", 0x40000: "SUBJECT_REQUIRE_COMMON_NAME", 0x80000: "SUBJECT_REQUIRE_DIRECTORY_PATH", 0x1000000: "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME", 0x2000000: "SUBJECT_ALT_REQUIRE_UPN", 0x4000000: "SUBJECT_ALT_REQUIRE_EMAIL", 0x8000000: "SUBJECT_ALT_REQUIRE_DNS", 0x20000000: "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID", 0x40000000: "SUBJECT_DNS_AS_CN_DEPRECATED", 0x80000000: "SUBJECT_DNS_AS_COMMON_NAME_DEPRECATED"}
MSPKI_ENROLLMENT_FLAG_MAP = {0x1: "INCLUDE_SYMMETRIC_ALGORITHMS", 0x2: "PEND_ALL_REQUESTS", 0x8: "PUBLISH_TO_DS", 0x10: "PUBLISH_TO_KRA_CONTAINER", 0x20: "AUTO_ENROLLMENT", 0x40: "PREVIOUS_APPROVAL_VALIDATE_ARCHIVED_KEY", 0x80: "DOMAIN_AUTHENTICATION_NOT_REQUIRED", 0x200: "ADD_BASIC_CONSTRAINTS_FOR_CAS", 0x40000: "ADD_TEMPLATE_TYPE", 0x80000: "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE", 0x20000: "USER_INTERACTION_REQUIRED", 0x400: "NO_SECURITY_EXTENSION", 0x100: "PUBLISH_TO_NTDS_CONTAINER"}
MSPKI_PRIVATE_KEY_FLAG_MAP = {0x1: "REQUIRE_KEY_ARCHIVAL", 0x10: "EXPORTABLE_KEY", 0x20: "STRONG_KEY_PROTECTION_REQUIRED", 0x80: "REQUIRE_SAME_KEY_RENEWAL", 0x100: "USE_LEGACY_PROVIDER", 0x200: "ATTEST_NONE", 0x400: "ATTEST_REQUIRED", 0x800: "ATTEST_PREFER_NONE", 0x1000: "ATTEST_PREFER_REQUIRED", 0x10000: "ATTEST_KEY_CONFIRMATION"}
PKI_TEMPLATE_GENERAL_FLAGS_MAP = { 0x1: "MACHINE_TYPE", 0x2: "IS_CA", 0x4: "ENROLLEE_SUPPLIES_SUBJECT_WHEN_REQUESTING_OFFLINE"}
PKI_CA_FLAGS_MAP = { 0x1: "SERVER_ONLINE" , 0x2: "SERVER_READONLY", 0x4: "ENTERPRISE_CA", 0x8: "ALLOW_AUTOREQUESTS_FROM_DS", 0x20: "ISSUANCE_POLICIES_DEFINED", 0x40: "IGNORE_MISSING_CRL_SIGNATURES", 0x20000: "ENFORCE_ENCRYPTION_FOR_REQUESTS"}
OID_MAP = {"1.3.6.1.5.5.7.3.1": "Server Authentication", "1.3.6.1.5.5.7.3.2": "Client Authentication", "1.3.6.1.5.5.7.3.3": "Code Signing", "1.3.6.1.5.5.7.3.4": "Secure Email", "1.3.6.1.4.1.311.10.3.3": "Encrypting File System", "1.3.6.1.4.1.311.21.5": "Private Key Archival", "1.3.6.1.4.1.311.21.6": "Key Recovery Agent", "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent", "1.3.6.1.5.2.3.4": "Kerberos Client Authentication", "1.3.6.1.5.2.3.5": "KDC Authentication", "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication", "1.3.6.1.5.5.7.3.9": "OCSP Signing", "2.5.29.37": "Any Purpose" }

def _parse_flags_to_list(flag_value_str, flag_map):
    parsed_flags = []
    if flag_value_str is None: return parsed_flags
    try:
        flag_value = int(flag_value_str)
        for name, bit in flag_map.items():
            if (flag_value & bit) == bit: parsed_flags.append(name)
        if not parsed_flags and flag_value == 0:
            if "NONE_FLAGS_SET" in flag_map and flag_map["NONE_FLAGS_SET"] == 0: parsed_flags.append("NONE_FLAGS_SET")
            elif "NONE" in flag_map and flag_map["NONE"] == 0 : parsed_flags.append("NONE")
        elif not parsed_flags and flag_value != 0: parsed_flags.append(f"UNKNOWN_FLAG_VALUE_{hex(flag_value)}")
    except (ValueError, TypeError): logging.warning(f"Could not parse flag value: {flag_value_str}")
    return parsed_flags

def _convert_pki_period_to_str(period_bytes):
    if not period_bytes or not isinstance(period_bytes, bytes) or len(period_bytes) != 8: return None 
    try:
        val = int.from_bytes(period_bytes, byteorder='little', signed=True)
        if val == 0: return "0 (Default or Disabled)"
        seconds = abs(val / 10_000_000) 
        if seconds == 0: return "0"
        if seconds % 31536000 == 0: years = int(seconds // 31536000); return f"{years} year{'s' if years > 1 else ''}"
        if seconds % 2592000 == 0: months = int(seconds // 2592000); return f"{months} month{'s' if months > 1 else ''}"
        if seconds % 604800 == 0: weeks = int(seconds // 604800); return f"{weeks} week{'s' if weeks > 1 else ''}"
        if seconds % 86400 == 0: days = int(seconds // 86400); return f"{days} day{'s' if days > 1 else ''}"
        days_approx = round(seconds / 86400)
        if days_approx > 365 * 1.5 : years_approx = round(days_approx/365); return f"~{years_approx} year{'s' if years_approx > 1 else ''}"
        if days_approx > 30 * 1.5 : months_approx = round(days_approx/30); return f"~{months_approx} month{'s' if months_approx > 1 else ''}"
        if days_approx > 7 * 1.5 : weeks_approx = round(days_approx/7); return f"~{weeks_approx} week{'s' if weeks_approx > 1 else ''}"
        return f"~{days_approx} day{'s' if days_approx > 1 else ''}"
    except Exception as e: logging.debug(f"Error converting PKI period bytes {b64encode(period_bytes).decode()}: {e}"); return f"Raw: {b64encode(period_bytes).decode()}"

def pull_all_ad_objects(ip: str, domain: str, username: str, auth: NTLMAuth, query: str, attributes: list, base_dn_override: str = None):
    effective_base_dn = base_dn_override if base_dn_override else "DC=" + ",DC=".join(domain.split('.'))
    logging.info(f"Collecting AD objects. Domain: {domain}, Query: '{query}', Base DN: {effective_base_dn}, Attributes: {len(attributes)}")
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    all_pulled_items = []
    pull_et_root_items = pull_client.pull(query=query, attributes=attributes, base_object_dn_for_soap=effective_base_dn)
    if pull_et_root_items is None:
        logging.error(f"ADWSConnect.pull returned None for query '{query}' and base '{effective_base_dn}'.")
        return {"objects": [], "domain_root_dn": "DC=" + ",DC=".join(domain.split('.')), "effective_base_dn_used": effective_base_dn}
    for item_elem in pull_et_root_items: 
        obj_data = {}
        for attr_name_original_case in attributes:
            attr_name_lower = attr_name_original_case.lower()
            attr_elems = item_elem.findall(f".//addata:{attr_name_original_case}/ad:value", namespaces=NAMESPACES)
            if not attr_elems and attr_name_original_case != attr_name_lower: 
                 attr_elems = item_elem.findall(f".//addata:{attr_name_lower}/ad:value", namespaces=NAMESPACES)
            if attr_elems:
                values = []
                for val_elem in attr_elems:
                    if val_elem.text is None: continue 
                    is_b64_by_type = val_elem.attrib.get('{http://www.w3.org/2001/XMLSchema-instance}type') == 'ad:base64Binary'
                    if is_b64_by_type or attr_name_lower in KNOWN_BINARY_ADWS_ATTRIBUTES:
                        if isinstance(val_elem.text, str): 
                            try: values.append(b64decode(val_elem.text))
                            except Exception as e: 
                                logging.debug(f"Failed b64decode for '{attr_name_original_case}' (value: '{val_elem.text[:30]}...'), storing as string. Error: {e}")
                                values.append(val_elem.text) 
                        else: values.append(val_elem.text) 
                    else: values.append(val_elem.text)
                if values:
                    obj_data[attr_name_original_case] = values[0] if len(values) == 1 and not isinstance(values[0], list) else values
        if 'distinguishedName' not in obj_data:
            dn_elem = item_elem.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
            if dn_elem is not None and dn_elem.text is not None: obj_data['distinguishedName'] = dn_elem.text
        if 'objectClass' not in obj_data:
            oc_val = [oc.text for oc in item_elem.findall(".//addata:objectClass/ad:value", namespaces=NAMESPACES) if oc.text]
            if oc_val: obj_data['objectClass'] = oc_val
        if obj_data.get('distinguishedName'):
            all_pulled_items.append(obj_data)
    logging.info(f"Parsed {len(all_pulled_items)} objects from ADWS response for query '{query}' (Base DN target: {effective_base_dn}).")
    return {"objects": all_pulled_items, "domain_root_dn": "DC=" + ",DC=".join(domain.split('.')),  "effective_base_dn_used": effective_base_dn}

def get_soaphound_type_id(dn, object_classes, object_sid_str, domain_root_dn):
    if not isinstance(object_classes, list): object_classes = [object_classes]
    object_classes_lower = [str(oc).lower() for oc in object_classes]
    if "pkicertificatetemplate" in object_classes_lower: return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("pkicertificatetemplate")
    if "certificationauthority" in object_classes_lower: return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("certificationauthority")
    if "pkienrollmentservice" in object_classes_lower: return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("pkienrollmentservice")
    if object_sid_str == "S-1-5-32": return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("builtindomain", 7)
    if object_sid_str == "S-1-5-17": return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("group", 2) 
    if dn and domain_root_dn and dn.lower() == domain_root_dn.lower(): return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("domaindns", 4)
    for oc_priority in SOAPHOUND_OBJECT_CLASS_PRIORITY:
        if oc_priority in object_classes_lower:
            type_id = SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get(oc_priority)
            if type_id is not None: return type_id
    if "container" in object_classes_lower: return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("container", 6)
    return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("container", 6) 

def _generate_individual_caches(all_pulled_items, domain_root_dn):
    logging.info("Generating individual cache dictionaries in memory for SOAPHound...")
    id_to_type_cache = {}
    value_to_id_cache = {} 
    for obj in all_pulled_items:
        dn = obj.get('distinguishedName')
        if not dn: continue
        raw_sid_bytes = obj.get('objectSid'); raw_guid_bytes = obj.get('objectGUID') 
        object_classes = obj.get('objectClass', [])
        
        sid_str = None 
        guid_str = None 

        if isinstance(raw_sid_bytes, bytes): 
            try: sid_str = LDAP_SID(raw_sid_bytes).formatCanonical()
            except Exception as e: logging.debug(f"Cache: Could not format SID for {dn}: {e}")
        elif isinstance(raw_sid_bytes, str):
             if raw_sid_bytes.upper().startswith("S-1-"): 
                sid_str = raw_sid_bytes.upper()
        
        if isinstance(raw_guid_bytes, bytes): 
            try: guid_str = str(UUID(bytes_le=raw_guid_bytes))
            except Exception as e: logging.debug(f"Cache: Could not format GUID for {dn}: {e}")
        elif isinstance(raw_guid_bytes, str) and len(raw_guid_bytes) == 36 : guid_str = raw_guid_bytes.lower()
        
        primary_id = sid_str 
        oc_lower_list_for_check = [str(oc).lower() for oc in object_classes] if isinstance(object_classes, list) else ([str(object_classes).lower()] if object_classes else [])
        
        if "cn=configuration,".lower() in dn.lower() or \
           "pkicertificatetemplate" in oc_lower_list_for_check or \
           "certificationauthority" in oc_lower_list_for_check or \
           "pkienrollmentservice" in oc_lower_list_for_check or \
           not sid_str: 
            primary_id = guid_str
        
        if not primary_id: 
            primary_id = sid_str or guid_str 
        
        if not primary_id: 
            logging.debug(f"Cache: Skipping object {dn} due to missing primary identifier (SID/GUID).")
            continue

        id_to_type_cache[primary_id] = get_soaphound_type_id(dn, object_classes, sid_str, domain_root_dn)
        value_to_id_cache[unicodedata.normalize('NFKC', dn).upper()] = primary_id
    logging.info(f"Generated {len(id_to_type_cache)} IdToType mappings and {len(value_to_id_cache)} ValueToId mappings.")
    return id_to_type_cache, value_to_id_cache

def create_and_combine_soaphound_cache(all_pulled_items, domain_root_dn, output_dir="."):
    combined_output_path = os.path.join(output_dir, "CombinedCache.json") 
    logging.info(f"Initiating SOAPHound cache generation to {combined_output_path}...")
    id_to_type_dict, value_to_id_dict = _generate_individual_caches(all_pulled_items, domain_root_dn)
    if not id_to_type_dict or not value_to_id_dict:
        logging.error("Failed to generate individual cache dictionaries. Combined cache not created."); return
    try:
        combined_data = {"IdToTypeCache": id_to_type_dict, "ValueToIdCache": value_to_id_dict}
        with open(combined_output_path, 'w', encoding='utf-8') as f: 
            json.dump(combined_data, f, indent=2, ensure_ascii=False)
        logging.info(f"CombinedCache.json saved to {combined_output_path}")
    except IOError as e: logging.error(f"Error writing cache files: {e}")

def _ldap_datetime_to_epoch(ldap_timestamp_val, is_lastlogontimestamp=False):
    if not ldap_timestamp_val or str(ldap_timestamp_val) in ['0', '9223372036854775807', '-1', '']:
        return -1 if is_lastlogontimestamp else 0 
    try:
        val_str = str(ldap_timestamp_val)
        if '.' in val_str and val_str.endswith('Z'): 
            dt_format = "%Y%m%d%H%M%S.%fZ" 
            if sys.version_info < (3, 7) and 'Z' in val_str: val_str = val_str[:-1]; dt_format = "%Y%m%d%H%M%S.%f"
            dt_obj = datetime.strptime(val_str, dt_format).replace(tzinfo=timezone.utc)
            return int(dt_obj.timestamp())
        else: 
            ft_int = int(val_str)
            epoch_diff_seconds = 11644473600 
            timestamp_secs = (ft_int / 10000000.0) - epoch_diff_seconds
            return int(timestamp_secs)
    except Exception as e: 
        logging.debug(f"Error converting timestamp '{ldap_timestamp_val}': {e}")
        return -1 if is_lastlogontimestamp else 0

def _parse_uac_flags(uac_value_str):
    flags = {}; 
    if uac_value_str is None: return flags
    try:
        uac = int(uac_value_str)
        flags["enabled"] = not bool(uac & 0x0002) 
        flags["passwordnotreqd"] = bool(uac & 0x0020) 
        flags["unconstraineddelegation"] = bool(uac & 0x080000) 
        flags["sensitive"] = bool(uac & 0x100000) 
        flags["dontreqpreauth"] = bool(uac & 0x400000) 
        flags["pwdneverexpires"] = bool(uac & 0x010000) 
        flags["trustedtoauth"] = bool(uac & 0x1000000) 
    except (ValueError, TypeError) as e: logging.warning(f"Could not parse UAC value '{uac_value_str}': {e}")
    return flags

def _resolve_principal_type_from_cache(principal_id, id_to_type_cache, default_bh_type="Base"):
    if not principal_id: return default_bh_type.capitalize()
    numeric_type = id_to_type_cache.get(principal_id)
    if numeric_type is not None: return BH_TYPE_LABEL_MAP.get(numeric_type, default_bh_type).capitalize()
    if isinstance(principal_id, str):
        if principal_id.upper().startswith("S-1-5-21-"): return "User" 
        if principal_id.upper().startswith("S-1-5-32-"): return "Group" 
        if principal_id.upper() == "S-1-1-0": return "Group" 
        if principal_id.upper() == "S-1-5-18": return "System" 
    logging.debug(f"Could not resolve type for PrincipalID '{principal_id}' from cache, defaulting to '{default_bh_type}'.")
    return default_bh_type.capitalize()

def _ace_applies(ace_guid_str, object_class_label, bh_object_class_guid_map):
    if not ace_guid_str or ace_guid_str == "00000000-0000-0000-0000-000000000000":
        return True 
    expected_class_guid = bh_object_class_guid_map.get(object_class_label.lower())
    if expected_class_guid and ace_guid_str == expected_class_guid.lower():
        return True
    return False

def _parse_aces(ntsd_bytes, id_to_type_cache, current_object_id, object_type_label_for_ace="Base", has_laps_prop=False):
    aces_list = []
    is_acl_protected = False 
    if not ntsd_bytes or not isinstance(ntsd_bytes, bytes): 
        return aces_list, is_acl_protected
    
    IGNORED_SIDS_FOR_DACL_ACES = ["S-1-3-0", "S-1-5-18", "S-1-5-10", "S-1-1-0"] 

    try:
        sd = SR_SECURITY_DESCRIPTOR(data=ntsd_bytes)
        if sd['Control'] & 0x1000: is_acl_protected = True
        
        if 'OwnerSid' in sd.fields and sd['OwnerSid'] and sd['OwnerSid'].getData(): 
            try:
                owner_sid_str = sd['OwnerSid'].formatCanonical()
                # Ne pas ignorer le Owner si c'est un SID valide.
                if owner_sid_str and owner_sid_str != "S-1-0-0": 
                    owner_type = _resolve_principal_type_from_cache(owner_sid_str, id_to_type_cache, "Unknown").capitalize()
                    aces_list.append({"PrincipalSID": owner_sid_str, "PrincipalType": owner_type, "RightName": "Owns", "IsInherited": False})
            except Exception as e_owner: logging.debug(f"Could not format OwnerSid for {current_object_id}: {e_owner}")

        dacl_present_flag_is_set = bool(sd['Control'] & 0x0004) 
        dacl_object_valid_and_has_aces = ('Dacl' in sd.fields and sd['Dacl'] is not None and hasattr(sd['Dacl'], 'aces') and sd['Dacl'].aces is not None)
        
        if dacl_present_flag_is_set and dacl_object_valid_and_has_aces:
            for ace_raw in sd['Dacl'].aces:
                ace_specific_structure = ace_raw['Ace'] 
                principal_sid_obj = None; principal_sid_str = f"ERROR_SID_UNRESOLVED"
                ace_mask_val = 0; current_ace_type = -1; ace_flags_raw = 0 
                object_type_guid_bytes = None; inherited_object_type_guid_bytes = None
                ace_internal_obj_flags = 0 

                try:
                    sid_field_from_impacket_ace = ace_specific_structure['Sid']
                    raw_sid_data = None
                    if isinstance(sid_field_from_impacket_ace, LDAP_SID): principal_sid_obj = sid_field_from_impacket_ace
                    elif isinstance(sid_field_from_impacket_ace, bytes): raw_sid_data = sid_field_from_impacket_ace
                    elif hasattr(sid_field_from_impacket_ace, 'getData') and callable(sid_field_from_impacket_ace.getData): raw_sid_data = sid_field_from_impacket_ace.getData()
                    else: continue 
                    if raw_sid_data and principal_sid_obj is None: principal_sid_obj = LDAP_SID(data=raw_sid_data)
                    if principal_sid_obj is None: continue
                    principal_sid_str = principal_sid_obj.formatCanonical()

                    if principal_sid_str in IGNORED_SIDS_FOR_DACL_ACES: continue 

                    ace_mask_val = int(ace_specific_structure['Mask']['Mask'])
                    current_ace_type = ace_raw['AceType']; ace_flags_raw = ace_raw['AceFlags']     
                    if current_ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE or current_ace_type == ACCESS_DENIED_OBJECT_ACE_TYPE:
                        if 'ObjectType' in ace_specific_structure.fields and ace_specific_structure['ObjectType'] is not None: object_type_guid_bytes = ace_specific_structure['ObjectType']
                        if 'InheritedObjectType' in ace_specific_structure.fields and ace_specific_structure['InheritedObjectType'] is not None: inherited_object_type_guid_bytes = ace_specific_structure['InheritedObjectType']
                        if 'Flags' in ace_specific_structure.fields: ace_internal_obj_flags = ace_specific_structure['Flags']
                except Exception: continue
                
                principal_type = _resolve_principal_type_from_cache(principal_sid_str, id_to_type_cache, "Unknown").capitalize()
                is_inherited_flag = bool(ace_flags_raw & ACE.INHERITED_ACE) 
                
                if not (current_ace_type == ACCESS_ALLOWED_ACE_TYPE or current_ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE): 
                    continue 

                temp_mapped_rights_for_this_ace = set() 
                is_object_ace = current_ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE
                ace_object_type_present = bool(ace_internal_obj_flags & ACE_OBJECT_TYPE_PRESENT) if is_object_ace else False
                
                object_type_guid_str = None
                if is_object_ace and ace_object_type_present and object_type_guid_bytes:
                    try: object_type_guid_str = str(UUID(bytes_le=object_type_guid_bytes)).lower()
                    except: pass
                
                # --- Logique de filtrage des ACEs pour se rapprocher de BloodHound.py ---
                is_generic_all_on_object = False
                applies_to_current_class = True # Simplification pour l'instant

                if is_object_ace and ace_object_type_present and object_type_guid_str and \
                   (ace_internal_obj_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) and inherited_object_type_guid_bytes:
                    try:
                        inherited_guid_str = str(UUID(bytes_le=inherited_object_type_guid_bytes)).lower()
                        if not _ace_applies(inherited_guid_str, object_type_label_for_ace, BH_EXTRIGHTS_GUID_MAPPING): # Utiliser BH_EXTRIGHTS_GUID_MAPPING pour les classes
                            continue 
                    except: continue

                if (ace_mask_val & ACCESS_MASK.GENERIC_ALL) == ACCESS_MASK.GENERIC_ALL:
                    if not is_object_ace or not ace_object_type_present or not object_type_guid_str or \
                       _ace_applies(object_type_guid_str, object_type_label_for_ace, BH_EXTRIGHTS_GUID_MAPPING):
                        temp_mapped_rights_for_this_ace.add("GenericAll")
                        is_generic_all_on_object = True
                        if object_type_label_for_ace == 'Computer' and has_laps_prop:
                             temp_mapped_rights_for_this_ace.add('ReadLAPSPassword')
                
                if not is_generic_all_on_object:
                    if (ace_mask_val & ACCESS_MASK.GENERIC_WRITE) == ACCESS_MASK.GENERIC_WRITE:
                         if not is_object_ace or not ace_object_type_present or not object_type_guid_str or \
                            _ace_applies(object_type_guid_str, object_type_label_for_ace, BH_EXTRIGHTS_GUID_MAPPING):
                            temp_mapped_rights_for_this_ace.add("GenericWrite")
                
                if (ace_mask_val & ACCESS_MASK.WRITE_DACL) == ACCESS_MASK.WRITE_DACL: temp_mapped_rights_for_this_ace.add("WriteDacl")
                if (ace_mask_val & ACCESS_MASK.WRITE_OWNER) == ACCESS_MASK.WRITE_OWNER: temp_mapped_rights_for_this_ace.add("WriteOwner")

                if (ace_mask_val & ADS_RIGHT_DS_CONTROL_ACCESS) == ADS_RIGHT_DS_CONTROL_ACCESS:
                    if is_object_ace and ace_object_type_present and object_type_guid_str:
                        mapped_right = BH_EXTRIGHTS_GUID_MAPPING.get(object_type_guid_str)
                        if mapped_right in INTERESTING_BH_GUID_RIGHTS_NAMES: temp_mapped_rights_for_this_ace.add(mapped_right)
                        elif mapped_right == "AllExtendedRights": temp_mapped_rights_for_this_ace.add("AllExtendedRights")
                    else: temp_mapped_rights_for_this_ace.add("AllExtendedRights")

                if (ace_mask_val & ADS_RIGHT_DS_WRITE_PROP) == ADS_RIGHT_DS_WRITE_PROP:
                    if is_object_ace and ace_object_type_present and object_type_guid_str:
                        mapped_right = BH_EXTRIGHTS_GUID_MAPPING.get(object_type_guid_str)
                        if mapped_right in INTERESTING_BH_GUID_RIGHTS_NAMES: 
                            temp_mapped_rights_for_this_ace.add(mapped_right)
                        # Ignorer les WriteProperty-GUID non "intéressants"
                    elif not is_object_ace or not ace_object_type_present: 
                        if object_type_label_for_ace in ['User', 'Group', 'Computer', 'GPO', 'OU'] and \
                           "GenericAll" not in temp_mapped_rights_for_this_ace and \
                           "GenericWrite" not in temp_mapped_rights_for_this_ace:
                             temp_mapped_rights_for_this_ace.add("GenericWrite")
                
                if (ace_mask_val & ADS_RIGHT_DS_READ_PROP) == ADS_RIGHT_DS_READ_PROP:
                    if object_type_label_for_ace == 'Computer' and has_laps_prop and \
                       is_object_ace and ace_object_type_present and object_type_guid_str and \
                       (object_type_guid_str == BH_EXTRIGHTS_GUID_MAPPING.get('ms-MCS-AdmPwdGuid') or \
                        object_type_guid_str == BH_EXTRIGHTS_GUID_MAPPING.get('msLAPS-PasswordGuid') or \
                        object_type_guid_str == BH_EXTRIGHTS_GUID_MAPPING.get('ComputerClassGuid') ):
                        temp_mapped_rights_for_this_ace.add("ReadLAPSPassword")
                    elif "GenericAll" in temp_mapped_rights_for_this_ace and object_type_label_for_ace == 'Computer' and has_laps_prop:
                         temp_mapped_rights_for_this_ace.add('ReadLAPSPassword') # Si GenericAll et LAPS, ajouter ReadLAPS

                if (ace_mask_val & ADS_RIGHT_DS_SELF) == ADS_RIGHT_DS_SELF and \
                   object_type_label_for_ace == "Group" and \
                   is_object_ace and ace_object_type_present and \
                   object_type_guid_str == BH_EXTRIGHTS_GUID_MAPPING.get("WriteMember"):
                    temp_mapped_rights_for_this_ace.add("AddSelf")
                
                # Déduction finale de GenericWrite si non déjà présent et si les conditions de BloodHound sont remplies
                if "GenericAll" not in temp_mapped_rights_for_this_ace and "GenericWrite" not in temp_mapped_rights_for_this_ace:
                    if (ace_mask_val & ACCESS_MASK.WRITE_DACL) and \
                       (ace_mask_val & ACCESS_MASK.WRITE_OWNER) and \
                       (ace_mask_val & ADS_RIGHT_DS_WRITE_PROP) and \
                       (not is_object_ace or not ace_object_type_present or not object_type_guid_str):
                           temp_mapped_rights_for_this_ace.add("GenericWrite")

                final_rights_for_ace = sorted(list(temp_mapped_rights_for_this_ace))
                if not final_rights_for_ace: continue 

                for right_name in final_rights_for_ace:
                    if right_name == "WriteOwner" and 'OwnerSid' in sd.fields and sd['OwnerSid'] and sd['OwnerSid'].getData():
                        try:
                            if principal_sid_str == sd['OwnerSid'].formatCanonical(): continue 
                        except Exception: pass
                    
                    is_duplicate_in_output = False
                    for existing_ace_output in aces_list:
                        if existing_ace_output["PrincipalSID"] == principal_sid_str and \
                           existing_ace_output["RightName"] == right_name and \
                           existing_ace_output["IsInherited"] == is_inherited_flag:
                            is_duplicate_in_output = True; break
                    if not is_duplicate_in_output:
                        aces_list.append({"PrincipalSID": principal_sid_str, "PrincipalType": principal_type, "RightName": right_name, "IsInherited": is_inherited_flag})
        
    except Exception as e:
        logging.error(f"Major failure parsing NTSecurityDescriptor for object {current_object_id}: {e}", exc_info=True)
        if logging.getLogger().isEnabledFor(logging.DEBUG) and ntsd_bytes: logging.debug(f"  NTSD Data (b64): {b64encode(ntsd_bytes).decode()}")
        return [], is_acl_protected
            
    return aces_list, is_acl_protected


def process_bloodhound_data(all_collected_items: list, domain_name: str, domain_root_dn: str, 
                            id_to_type_cache: dict, value_to_id_cache: dict):
    logging.info(f"Processing {len(all_collected_items)} items for BloodHound for domain: {domain_name}")
    
    users_bh, computers_bh, groups_bh, domains_bh, ous_bh, gpos_bh, containers_bh = [], [], [], [], [], [], []
    cas_bh, cert_templates_bh = [], [] 
    
    domain_sid_str, domain_guid_str = "", "" 
    main_domain_item_data = None; main_domain_gplinks = []; main_domain_item_props_collector = {}

    for item_domain_check in all_collected_items:
        item_dn_lower_check = item_domain_check.get("distinguishedName", "").lower()
        oc_list_raw_check = item_domain_check.get("objectClass", [])
        oc_list_lower_check = [str(oc).lower() for oc in oc_list_raw_check] if isinstance(oc_list_raw_check, list) else ([str(oc_list_raw_check).lower()] if oc_list_raw_check else [])
        is_domain_object_class = any(cls in oc_list_lower_check for cls in ["domain", "domaindns"])
        if is_domain_object_class and item_dn_lower_check == domain_root_dn.lower():
            main_domain_item_data = item_domain_check
            sid_bytes_check = item_domain_check.get("objectSid"); guid_bytes_check = item_domain_check.get("objectGUID")
            if isinstance(sid_bytes_check, bytes):
                try: domain_sid_str = LDAP_SID(sid_bytes_check).formatCanonical()
                except Exception as e: logging.warning(f"Error formatting domain SID: {e}")
            elif isinstance(sid_bytes_check, str) and sid_bytes_check.upper().startswith("S-1-"): domain_sid_str = sid_bytes_check.upper()
            if isinstance(guid_bytes_check, bytes):
                try: domain_guid_str = str(UUID(bytes_le=guid_bytes_check))
                except Exception as e: logging.warning(f"Error formatting domain GUID: {e}")
            elif isinstance(guid_bytes_check, str) and len(guid_bytes_check) == 36: domain_guid_str = guid_bytes_check.lower()
            if item_domain_check.get("description"): main_domain_item_props_collector["description"] = item_domain_check["description"]
            if item_domain_check.get("whenCreated"): main_domain_item_props_collector["whencreated"] = _ldap_datetime_to_epoch(item_domain_check.get("whenCreated"))
            if item_domain_check.get("msDS-Behavior-Version"): main_domain_item_props_collector["functionallevel"] = str(item_domain_check["msDS-Behavior-Version"])
            raw_gplinks_domain = item_domain_check.get("gPLink", [])
            gplink_values_domain = raw_gplinks_domain if isinstance(raw_gplinks_domain, list) else ([raw_gplinks_domain] if raw_gplinks_domain else [])
            for gplink_str_domain in gplink_values_domain:
                if not gplink_str_domain or not isinstance(gplink_str_domain, str): continue
                try:
                    link_part_domain, options_part_domain = gplink_str_domain.split(';', 1)
                    if not link_part_domain.lower().startswith("[ldap://"): continue
                    link_dn_domain = link_part_domain[len("[ldap://"):].strip("]")
                    link_options_domain = int(options_part_domain.strip('[]')) 
                    gpo_id_for_link_domain = value_to_id_cache.get(link_dn_domain.upper()) 
                    if gpo_id_for_link_domain and _resolve_principal_type_from_cache(gpo_id_for_link_domain, id_to_type_cache, "Gpo") == "Gpo":
                        main_domain_gplinks.append({"IsEnforced": bool(link_options_domain & 0x1), "GUID": gpo_id_for_link_domain.upper()})
                except Exception as e_gplink_domain: logging.warning(f"Could not parse gPLink '{gplink_str_domain}' for domain: {e_gplink_domain}")
            break 
            
    domain_props = {"name": domain_name.upper(), "domainsid": domain_sid_str, "distinguishedname": domain_root_dn.upper(), "highvalue": True}
    if domain_guid_str: domain_props["objectguid"] = domain_guid_str 
    domain_props.update(main_domain_item_props_collector)
    
    domain_sid_history_raw = main_domain_item_data.get("sIDHistory", []) if main_domain_item_data else []
    domain_sid_history_list = []
    if domain_sid_history_raw:
        raw_list = domain_sid_history_raw if isinstance(domain_sid_history_raw, list) else [domain_sid_history_raw]
        for sid_bytes_hist_dom in raw_list: 
            if isinstance(sid_bytes_hist_dom, bytes):
                try: domain_sid_history_list.append(LDAP_SID(sid_bytes_hist_dom).formatCanonical())
                except: pass
            elif isinstance(sid_bytes_hist_dom, str) and sid_bytes_hist_dom.upper().startswith("S-1-"):
                domain_sid_history_list.append(sid_bytes_hist_dom.upper())
    domain_props["sidhistory"] = domain_sid_history_list 

    aces_domain_data_source = main_domain_item_data if main_domain_item_data else {}
    aces_domain, is_acl_protected_domain = _parse_aces(aces_domain_data_source.get("nTSecurityDescriptor"), id_to_type_cache, domain_sid_str or domain_guid_str, "Domain")
    
    domain_bh_entry = {
        "ObjectIdentifier": domain_sid_str or domain_guid_str, 
        "Name": domain_name.upper(), "ObjectType": "Domain", 
        "IsDeleted": False, "IsACLProtected": is_acl_protected_domain,
        "Properties": domain_props, "Aces": aces_domain, "Trusts": [], "Links": main_domain_gplinks, 
        "ChildObjects": [], "HasSIDHistory": domain_sid_history_list 
    }
    if main_domain_item_data and main_domain_item_data.get("gPCFileSysPath") is not None :
         domain_bh_entry["GPOChanges"] = {"AffectedComputers": [], "DcomUsers": [], "LocalAdmins": [], "PSRemoteUsers": [], "RemoteDesktopUsers": []}
    domains_bh.append(domain_bh_entry)
    
    trusts_for_main_domain_node = []
    template_to_ca_map = {} 
    for item_ca_check in all_collected_items:
        oc_list_raw_ca = item_ca_check.get("objectClass", [])
        oc_list_lower_ca = [str(oc).lower() for oc in oc_list_raw_ca] if isinstance(oc_list_raw_ca, list) else ([str(oc_list_raw_ca).lower()] if oc_list_raw_ca else [])
        if "certificationauthority" in oc_list_lower_ca or "pkienrollmentservice" in oc_list_lower_ca:
            ca_name = (item_ca_check.get("name") or item_ca_check.get("cn","")).upper()
            published_templates_attr = item_ca_check.get("certificateTemplates", [])
            actual_published_templates = published_templates_attr if isinstance(published_templates_attr, list) else ([published_templates_attr] if published_templates_attr else [])
            for template_cn in actual_published_templates:
                if template_cn and isinstance(template_cn, str):
                    template_cn_upper = template_cn.upper()
                    if template_cn_upper not in template_to_ca_map: template_to_ca_map[template_cn_upper] = []
                    if ca_name not in template_to_ca_map[template_cn_upper]: template_to_ca_map[template_cn_upper].append(ca_name)

    for item in all_collected_items:
        oc_list_raw = item.get("objectClass", []); oc_list_lower = [str(oc).lower() for oc in oc_list_raw] if isinstance(oc_list_raw, list) else ([str(oc_list_raw).lower()] if oc_list_raw else [])
        dn = item.get("distinguishedName", "")
        if not dn or (("domain" in oc_list_lower or "domaindns" in oc_list_lower) and dn.lower() == domain_root_dn.lower()): continue

        sid_bytes = item.get('objectSid'); guid_bytes = item.get('objectGUID')
        current_item_sid_str, current_item_guid_str = "", "" 
        if isinstance(sid_bytes, bytes): 
            try: current_item_sid_str = LDAP_SID(sid_bytes).formatCanonical()
            except: pass
        elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"): current_item_sid_str = sid_bytes.upper()
        if isinstance(guid_bytes, bytes):
            try: current_item_guid_str = str(UUID(bytes_le=guid_bytes))
            except: pass
        elif isinstance(guid_bytes, str) and len(guid_bytes) == 36: current_item_guid_str = guid_bytes.lower()
        
        obj_type_bh, object_identifier = None, None
        id_for_type_lookup = current_item_sid_str
        is_pki_or_config_item = "cn=configuration,".lower() in dn.lower() or \
                           any(pki_oc in oc_list_lower for pki_oc in ["pkicertificatetemplate", "certificationauthority", "pkienrollmentservice"])
        if is_pki_or_config_item or not current_item_sid_str: 
            id_for_type_lookup = current_item_guid_str 
        if not id_for_type_lookup: id_for_type_lookup = current_item_guid_str or current_item_sid_str

        if "computer" in oc_list_lower: obj_type_bh = "Computer"; object_identifier = current_item_sid_str
        elif "user" in oc_list_lower: obj_type_bh = "User"; object_identifier = current_item_sid_str
        elif "group" in oc_list_lower: obj_type_bh = "Group"; object_identifier = current_item_sid_str
        elif "organizationalunit" in oc_list_lower: obj_type_bh = "OU"; object_identifier = current_item_guid_str
        elif "grouppolicycontainer" in oc_list_lower: obj_type_bh = "GPO"; object_identifier = current_item_guid_str
        elif "container" in oc_list_lower or "rpccontainer" in oc_list_lower: obj_type_bh = "Container"; object_identifier = current_item_guid_str or dn.upper()
        elif "trusteddomain" in oc_list_lower: obj_type_bh = "DomainTrust"; object_identifier = current_item_sid_str
        elif "certificationauthority" in oc_list_lower or "pkienrollmentservice" in oc_list_lower : obj_type_bh = "CA"; object_identifier = current_item_guid_str
        elif "pkicertificatetemplate" in oc_list_lower: obj_type_bh = "CertTemplate"; object_identifier = current_item_guid_str
        else: 
            obj_type_from_cache = _resolve_principal_type_from_cache(id_for_type_lookup, id_to_type_cache) if id_for_type_lookup else "Base"
            if obj_type_from_cache != "Base": 
                obj_type_bh = obj_type_from_cache; object_identifier = id_for_type_lookup
            else: logging.debug(f"Skipping object {dn} - unmapped type: {oc_list_lower}"); continue
            
        if not object_identifier: 
            logging.warning(f"Skipping object {dn} (type {obj_type_bh or 'Unknown'}) - missing ObjectIdentifier."); continue
        
        props = {"domain": domain_name.upper(), "distinguishedname": dn.upper()}
        if obj_type_bh in ["User", "Group", "Computer"]:
             if domain_sid_str : props["domainsid"] = domain_sid_str 
        
        name_attr = item.get("name") or item.get("cn"); sam_name = item.get("sAMAccountName")
        prop_name_val = "" ; top_level_name_val = ""

        if obj_type_bh in ["User", "Group"] and sam_name:
            prop_name_val = f"{sam_name.upper()}@{domain_name.upper()}"
            props["samaccountname"] = sam_name
        elif obj_type_bh == "Computer":
            if sam_name: props["samaccountname"] = sam_name 
            dns_hostname = item.get("dNSHostName")
            if dns_hostname: prop_name_val = dns_hostname.upper(); props["dnshostname"] = dns_hostname.upper()
            elif sam_name: clean_sam = sam_name[:-1] if sam_name.endswith('$') else sam_name; prop_name_val = f"{clean_sam.upper()}.{domain_name.upper()}"
            elif name_attr: prop_name_val = f"{name_attr.upper()}.{domain_name.upper()}"
            else: prop_name_val = (dn.split(',')[0].split('=')[-1]).upper() + f".{domain_name.upper()}"
            top_level_name_val = prop_name_val 
        elif obj_type_bh in ["CA", "CertTemplate"]:
            pki_name_base = item.get("displayName") or name_attr or dn.split(',')[0].split('=')[-1]
            prop_name_val = f"{pki_name_base.upper()}@{domain_name.upper()}" 
            if item.get("displayName"): props["displayname"] = item.get("displayName")
            if obj_type_bh == "CertTemplate" and name_attr : props["TemplateName"] = name_attr.upper() 
            elif obj_type_bh == "CA" and name_attr : props["CAName"] = name_attr.upper() 
            top_level_name_val = prop_name_val 
        elif name_attr : 
            prop_name_val = name_attr.upper()
            if obj_type_bh in ["OU", "GPO", "Container", "Domain"] and "@" not in prop_name_val and domain_name not in prop_name_val: prop_name_val = f"{prop_name_val}@{domain_name.upper()}"
            top_level_name_val = prop_name_val
        else:
            rdn_part = dn.split(',')[0]
            prop_name_val = (rdn_part.split('=',1)[-1] if '=' in rdn_part else rdn_part).upper()
            if obj_type_bh in ["OU", "GPO", "Container", "Domain"] and "@" not in prop_name_val and domain_name not in prop_name_val: prop_name_val = f"{prop_name_val}@{domain_name.upper()}"
            top_level_name_val = prop_name_val
        props["name"] = prop_name_val
        
        # Common string properties to null if not present for all types initially
        common_string_properties_all_types = ["description", "displayName", "title", "homeDirectory", "logonscript", "userpassword", "unixpassword", "unicodepassword", "sfupassword", "mail"]
        for prop_key in common_string_properties_all_types:
            props[prop_key] = item.get(prop_key.lower(), None) # Use .get with default None

        props["whencreated"] = _ldap_datetime_to_epoch(item.get("whenCreated"))
        props["lastlogon"] = _ldap_datetime_to_epoch(item.get("lastLogon"))
        props["lastlogontimestamp"] = _ldap_datetime_to_epoch(item.get("lastLogonTimestamp"), is_lastlogontimestamp=True)
        props["pwdlastset"] = _ldap_datetime_to_epoch(item.get("pwdLastSet"))
        
        current_sid_history_list = [] 
        sid_history_raw_node = item.get("sIDHistory")
        if sid_history_raw_node:
            processed_list = sid_history_raw_node if isinstance(sid_history_raw_node, list) else [sid_history_raw_node]
            for sid_bytes_hist_node in processed_list: 
                if isinstance(sid_bytes_hist_node, bytes):
                    try: current_sid_history_list.append(LDAP_SID(sid_bytes_hist_node).formatCanonical())
                    except: logging.debug(f"Could not parse sIDHistory value for {dn}")
                elif isinstance(sid_bytes_hist_node, str) and sid_bytes_hist_node.upper().startswith("S-1-"):
                    current_sid_history_list.append(sid_bytes_hist_node.upper())
        props["sidhistory"] = current_sid_history_list 

        # Highvalue logic specific to type
        if obj_type_bh == "Group" and current_item_sid_str and any(current_item_sid_str.endswith(s) for s in ["-512", "-516", "-519", "S-1-5-32-544"]): props["highvalue"] = True
        elif obj_type_bh == "OU" and props.get("name","").upper().startswith("DOMAIN CONTROLLERS@"): props["highvalue"] = True
        elif obj_type_bh != "Domain": # Domain highvalue is set with domain_props
             props["highvalue"] = False # Default for most other types
        
        spns_raw = item.get("servicePrincipalName")
        if spns_raw: props["serviceprincipalnames"] = spns_raw if isinstance(spns_raw, list) else ([spns_raw] if spns_raw else [])
        elif obj_type_bh in ["User", "Computer"]: props["serviceprincipalnames"] = []
        
        has_laps_prop_for_ace = bool(item.get("ms-MCS-AdmPwdExpirationTime")) if obj_type_bh == "Computer" else False
        current_ntsd_bytes = item.get("nTSecurityDescriptor")
        aces_list_for_node, is_acl_protected_node = _parse_aces(current_ntsd_bytes, id_to_type_cache, object_identifier, obj_type_bh, has_laps_prop_for_ace)
        
        bh_node = {
            "ObjectIdentifier": object_identifier, 
            "IsDeleted": False, "IsACLProtected": is_acl_protected_node, 
            "Properties": props, "Aces": aces_list_for_node,
            "HasSIDHistory": current_sid_history_list 
        }
        if obj_type_bh not in ["User", "Group"]:
            bh_node["Name"] = top_level_name_val 
            bh_node["ObjectType"] = obj_type_bh
            if current_item_guid_str and "objectguid" not in props : props["objectguid"] = current_item_guid_str # Add if not already in props
        elif "name" not in props: props["name"] = top_level_name_val

        if obj_type_bh == "User":
            props["hasspn"] = bool(props.get("serviceprincipalnames"))
            if item.get("userAccountControl"): props.update(_parse_uac_flags(item.get("userAccountControl")))
            else: 
                default_uac_flags = {"enabled": False, "passwordnotreqd": False, "unconstraineddelegation": False, "sensitive": False, "dontreqpreauth": False, "pwdneverexpires": False, "trustedtoauth": False}
                for k,v_default in default_uac_flags.items():
                    if k not in props: props[k] = v_default
            props["admincount"] = True if item.get("adminCount") == "1" else False
            
            if "objectguid" in props: del props["objectguid"]
            if "highvalue" in props: del props["highvalue"] 

            primary_group_id_val = item.get("primaryGroupID")
            if primary_group_id_val and current_item_sid_str : 
                try: bh_node["PrimaryGroupSID"] = f"{current_item_sid_str.rsplit('-',1)[0]}-{int(primary_group_id_val)}"
                except: bh_node["PrimaryGroupSID"] = None
            else: bh_node["PrimaryGroupSID"] = None
            
            member_of_dns = item.get("memberOf",[]); member_of_list_user = member_of_dns if isinstance(member_of_dns, list) else ([member_of_dns] if member_of_dns else [])
            bh_node["MemberOf"] = [value_to_id_cache.get(m.upper()) for m in member_of_list_user if m and isinstance(m, str) and value_to_id_cache.get(m.upper())]
            bh_node["AllowedToDelegate"] = [] 
            bh_node["AllowedToAct"] = [] 
            bh_node["SPNTargets"] = [] 
            users_bh.append(bh_node)
        elif obj_type_bh == "Computer":
            if "dnshostname" not in props: props["dnshostname"] = item.get("dNSHostName")
            if current_item_guid_str and "objectguid" not in props: props["objectguid"] = current_item_guid_str 
            if "highvalue" not in props: props["highvalue"] = False 

            if item.get("userAccountControl"): props.update(_parse_uac_flags(item.get("userAccountControl")))
            else: 
                default_uac_flags = {"enabled": True, "passwordnotreqd": False, "unconstraineddelegation": False, "sensitive": False, "dontreqpreauth": False, "pwdneverexpires": False, "trustedtoauth": False}
                for k,v_default in default_uac_flags.items():
                    if k not in props: props[k] = v_default
            props["haslaps"] = bool(item.get("ms-MCS-AdmPwdExpirationTime")) 
            if "operatingsystem" not in props: props["operatingsystem"] = item.get("operatingSystem", None)

            allowed_to_delegate_spns_raw = item.get("msDS-AllowedToDelegateTo", [])
            props["msds-allowedtodelegateto"] = allowed_to_delegate_spns_raw if isinstance(allowed_to_delegate_spns_raw, list) else ([allowed_to_delegate_spns_raw] if allowed_to_delegate_spns_raw else [])
            bh_node["AllowedToDelegate"] = [] 
            allowed_to_act_sddl = item.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
            if allowed_to_act_sddl: props["msds-allowedtoactonbehalfofotheridentity_sddl_b64"] = b64encode(allowed_to_act_sddl).decode() if isinstance(allowed_to_act_sddl, bytes) else allowed_to_act_sddl
            bh_node["AllowedToAct"] = []
            member_of_dns_comp = item.get("memberOf", []); member_of_list_comp = member_of_dns_comp if isinstance(member_of_dns_comp, list) else ([member_of_dns_comp] if member_of_dns_comp else [])
            bh_node["MemberOf"] = [value_to_id_cache.get(m.upper()) for m in member_of_list_comp if m and isinstance(m, str) and value_to_id_cache.get(m.upper())]
            
            primary_group_id_comp_val = item.get("primaryGroupID")
            if primary_group_id_comp_val and current_item_sid_str: 
                try: bh_node["PrimaryGroupSID"] = f"{current_item_sid_str.rsplit('-',1)[0]}-{int(primary_group_id_comp_val)}"
                except: bh_node["PrimaryGroupSID"] = None
            else: bh_node["PrimaryGroupSID"] = None
            
            bh_node["LocalAdmins"] = {"Collected": False, "FailureReason": None, "Results": [] }; bh_node["PSRemoteUsers"] = {"Collected": False, "FailureReason": None, "Results": [] }
            bh_node["RemoteDesktopUsers"] = {"Collected": False, "FailureReason": None, "Results": [] }; bh_node["DcomUsers"] = {"Collected": False, "FailureReason": None, "Results": [] }
            bh_node["PrivilegedSessions"] = {"Collected": False, "FailureReason": None, "Results": [] }; bh_node["Sessions"] = {"Collected": False, "FailureReason": None, "Results": [] } 
            bh_node["RegistrySessions"] = {"Collected": False, "FailureReason": None, "Results": [] } 
            bh_node["SPNTargets"] = [] 
            computers_bh.append(bh_node)
        elif obj_type_bh == "Group":
            props["admincount"] = True if item.get("adminCount") == "1" else False
            if "objectguid" in props: del props["objectguid"]
            if "domainsid" in props: del props["domainsid"] 
            if "highvalue" not in props: props["highvalue"] = False # Default for groups not otherwise marked

            members_processed = []
            raw_members = item.get("member", [])
            member_list_group = raw_members if isinstance(raw_members, list) else ([raw_members] if raw_members else [])
            for m_dn in member_list_group:
                if m_dn and isinstance(m_dn, str):
                    principal_id = value_to_id_cache.get(m_dn.upper())
                    if principal_id:
                        principal_type_numeric = id_to_type_cache.get(principal_id)
                        principal_type_label = BH_TYPE_LABEL_MAP.get(principal_type_numeric, "Base").capitalize()
                        members_processed.append({"ObjectIdentifier": principal_id, "ObjectType": principal_type_label})
            bh_node["Members"] = members_processed
            groups_bh.append(bh_node)
        elif obj_type_bh == "OU":
            if item.get("gPOptions") is not None: 
                try: props["blocksinheritance"] = bool(int(item.get("gPOptions")) & 0x1)
                except: props["blocksinheritance"] = False
            else: props["blocksinheritance"] = False 
            gplinks_processed_ou = []
            raw_gplinks_ou = item.get("gPLink", [])
            gplink_values_ou = raw_gplinks_ou if isinstance(raw_gplinks_ou, list) else ([raw_gplinks_ou] if raw_gplinks_ou else [])
            for gplink_str_ou in gplink_values_ou:
                if not gplink_str_ou or not isinstance(gplink_str_ou, str): continue
                try:
                    link_part_ou, options_part_ou = gplink_str_ou.split(';', 1)
                    if not link_part_ou.lower().startswith("[ldap://"): continue
                    link_dn_ou = link_part_ou[len("[ldap://"):].strip("]")
                    link_options_ou = int(options_part_ou.strip('[]')) 
                    gpo_id_for_link_ou = value_to_id_cache.get(link_dn_ou.upper()) 
                    if gpo_id_for_link_ou and _resolve_principal_type_from_cache(gpo_id_for_link_ou, id_to_type_cache, "Gpo") == "Gpo":
                        gplinks_processed_ou.append({"IsEnforced": bool(link_options_ou & 0x1), "GUID": gpo_id_for_link_ou.upper()})
                except Exception as e_gplink_ou: logging.warning(f"Could not parse gPLink '{gplink_str_ou}' for OU {dn}: {e_gplink_ou}")
            bh_node["Links"] = gplinks_processed_ou
            bh_node["ChildObjects"] = [] 
            bh_node["GPOChanges"] = { "LocalAdmins": [], "RemoteDesktopUsers": [], "DcomUsers": [], "PSRemoteUsers": [], "AffectedComputers": [] }
            ous_bh.append(bh_node)
        elif obj_type_bh == "GPO":
            if item.get("displayName"): props["displayname"] = item["displayName"] 
            if item.get("gPCFileSysPath"): props["gpcpath"] = item.get("gPCFileSysPath")
            bh_node["GPOChanges"] = {"AffectedComputers": [], "DcomUsers": [], "LocalAdmins": [], "PSRemoteUsers": [], "RemoteDesktopUsers": []}
            gpos_bh.append(bh_node)
        elif obj_type_bh == "Container":
            props["highvalue"] = ("CN=DOMAIN CONTROLLERS" in dn.upper()) 
            bh_node["ChildObjects"] = []
            containers_bh.append(bh_node)
        elif obj_type_bh == "DomainTrust":
            target_name = item.get("name") or item.get("flatName") or item.get("cn")
            trust_direction_val = item.get("trustDirection", "0"); trust_attributes_val = item.get("trustAttributes", "0")
            is_transitive = True; sid_filtering = False; trust_type_bh_val = 4 
            if trust_attributes_val:
                try:
                    attrs = int(trust_attributes_val)
                    if attrs & 0x1: is_transitive = False 
                    if attrs & 0x4: sid_filtering = True  
                    if attrs & 0x20: trust_type_bh_val = 0 
                    elif attrs & 0x8: trust_type_bh_val = 2 
                    elif attrs & 0x40 or attrs & 0x10 : trust_type_bh_val = 3 
                except: pass
            trust_entry = {"TargetDomainSid": object_identifier, "TargetDomainName": (target_name.upper() if target_name else "UNKNOWN_TRUST"),
                           "IsTransitive": is_transitive, "SidFilteringEnabled": sid_filtering,
                           "TrustDirection": int(trust_direction_val) if trust_direction_val else 0, "TrustType": trust_type_bh_val}
            trusts_for_main_domain_node.append(trust_entry)
        elif obj_type_bh == "CA":
            props["CAName"] = (item.get("name") or item.get("cn","")).upper() 
            if item.get("dNSHostName"): props["DNSName"] = item.get("dNSHostName").upper()
            if CRYPTOGRAPHY_AVAILABLE and item.get("cACertificate"):
                certs_data = item.get("cACertificate"); certs_list_bytes = certs_data if isinstance(certs_data, list) else ([certs_data] if certs_data else [])
                if certs_list_bytes and isinstance(certs_list_bytes[0], bytes):
                    try:
                        cert = x509.load_der_x509_certificate(certs_list_bytes[0])
                        props["CertificateSubject"] = cert.subject.rfc4514_string()
                        props["CertificateSerialNumber"] = cert.serial_number.to_bytes((cert.serial_number.bit_length() + 7) // 8, 'big').hex().upper()
                        props["CertificateValidityStart"] = cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
                        props["CertificateValidityEnd"] = cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
                    except Exception as e_cert: logging.warning(f"Could not parse CA certificate for {dn}: {e_cert}")
            props["PublishedCertificateTemplates"] = item.get("certificateTemplates", []) 
            props["CAType"] = "EnrollmentService" 
            props["CAFlags"] = _parse_flags_to_list(item.get("flags"), PKI_CA_FLAGS_MAP)
            props["WebEnrollment"] = "Unknown"; props["UserSuppliedSAN"] = "Unknown"; props["RequestDisposition"] = "Unknown"; props["EnforceEncryptionForRequests"] = "Unknown";
            cas_bh.append(bh_node)
        elif obj_type_bh == "CertTemplate":
            props["DisplayName"] = item.get("displayName", props.get("name"))
            props["TemplateName"] = (item.get("cn") or item.get("name","")).upper()
            if item.get("msPKI-Cert-Template-OID"): props["OID"] = item.get("msPKI-Cert-Template-OID")
            template_flags_val = int(item.get("Flags", 0)) if item.get("Flags") else 0
            props["Enabled"] = not bool(template_flags_val & 0x2) 
            enroll_flags_val = int(item.get("msPKI-Enrollment-Flag", 0)) if item.get("msPKI-Enrollment-Flag") else 0
            props["RequiresManagerApproval"] = bool(enroll_flags_val & 0x2) 
            props["CertificateNameFlags"] = _parse_flags_to_list(item.get("msPKI-Certificate-Name-Flag"), MSPKI_CERTIFICATE_NAME_FLAG_MAP)
            props["EnrollmentFlags"] = _parse_flags_to_list(str(enroll_flags_val), MSPKI_ENROLLMENT_FLAG_MAP)
            props["PrivateKeyFlags"] = _parse_flags_to_list(item.get("msPKI-Private-Key-Flag"), MSPKI_PRIVATE_KEY_FLAG_MAP)
            ekus_raw = item.get("pKIExtendedKeyUsage", []); ekus_list = ekus_raw if isinstance(ekus_raw, list) else ([ekus_raw] if ekus_raw else [])
            props["ExtendedKeyUsages"] = [OID_MAP.get(eku_oid, eku_oid) for eku_oid in ekus_list if eku_oid]
            props["ClientAuthentication"] = "Client Authentication" in props["ExtendedKeyUsages"] or "Any Purpose" in props["ExtendedKeyUsages"] or not props["ExtendedKeyUsages"]
            props["EnrollmentAgent"] = "Certificate Request Agent" in props["ExtendedKeyUsages"]
            props["EnrolleeSuppliesSubject"] = "ENROLLEE_SUPPLIES_SUBJECT" in props["CertificateNameFlags"]
            props["ValidityPeriod"] = _convert_pki_period_to_str(item.get("pKIExpirationPeriod"))
            props["RenewalPeriod"] = _convert_pki_period_to_str(item.get("pKIOverlapPeriod"))
            if item.get("msPKI-Minimal-Key-Size"): props["MinimumKeyLength"] = int(item.get("msPKI-Minimal-Key-Size"))
            props["AuthorizedSignatures"] = int(item.get("msPKI-RA-Signature",0)) if item.get("msPKI-RA-Signature") else 0
            props["CertificateAuthorities"] = template_to_ca_map.get(props["TemplateName"], [])
            props["SchemaVersion"] = item.get("msPKI-Template-Schema-Version")
            props["Type"] = "Certificate Template" 
            cert_templates_bh.append(bh_node)
            
    all_nodes_for_child_lookup = domains_bh + ous_bh + containers_bh
    for parent_node in all_nodes_for_child_lookup:
        if not parent_node.get("Properties", {}).get("distinguishedname"): continue
        parent_dn_upper = parent_node["Properties"]["distinguishedname"].upper()
        child_objects_list = []
        for item_dn_child_upper, item_child_id in value_to_id_cache.items(): 
            if item_dn_child_upper != parent_dn_upper and item_dn_child_upper.endswith("," + parent_dn_upper):
                if item_dn_child_upper.count(',') == parent_dn_upper.count(',') + 1:
                    child_type_numeric = id_to_type_cache.get(item_child_id)
                    child_type_label = BH_TYPE_LABEL_MAP.get(child_type_numeric, "Base").capitalize()
                    child_objects_list.append({"ObjectIdentifier": item_child_id, "ObjectType": child_type_label})
        parent_node["ChildObjects"] = child_objects_list
    
    if domains_bh: 
        domains_bh[0]["Trusts"] = trusts_for_main_domain_node

    output_base_name = f"soapyhound-{domain_name.lower()}"
    def write_json_file(data, filename_suffix, data_type_meta_input, version=5): 
        if not data: logging.debug(f"No data for {data_type_meta_input}, skipping file generation for {filename_suffix}.json"); return
        
        meta_type_for_file = data_type_meta_input 
        if data_type_meta_input == "cas": meta_type_for_file = "cas" 
        elif data_type_meta_input == "certificatetemplates": meta_type_for_file = "certificatetemplates"

        file_path = os.path.join(".", f"{output_base_name}_{filename_suffix}.json") 
        output_data = {
            "data": data, 
            "meta": {
                "methods": 0, 
                "type": meta_type_for_file, 
                "version": version, 
                "count": len(data),
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            }
        }
        try:
            with open(file_path, 'w', encoding='utf-8') as f: json.dump(output_data, f, ensure_ascii=False, indent=4) 
            logging.info(f"BloodHound data written to {file_path} ({len(data)} {data_type_meta_input}).")
        except IOError as e: logging.error(f"Error writing to file {file_path}: {e}")

    write_json_file(users_bh, "users", "users", version=5)
    write_json_file(computers_bh, "computers", "computers", version=5)
    write_json_file(groups_bh, "groups", "groups", version=5)
    write_json_file(domains_bh, "domains", "domains", version=5)
    write_json_file(ous_bh, "ous", "ous", version=5)
    write_json_file(gpos_bh, "gpos", "gpos", version=5) 
    write_json_file(containers_bh, "containers", "containers", version=5) 
    if cas_bh : write_json_file(cas_bh, "cas", "cas", version=4) 
    if cert_templates_bh : write_json_file(cert_templates_bh, "certificatetemplates", "certificatetemplates", version=4) 

    logging.info("BloodHound data processing complete.")