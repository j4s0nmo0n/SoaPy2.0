import json
import logging
import unicodedata
from base64 import b64decode, b64encode
from uuid import UUID
import os
from datetime import datetime, timezone, timedelta # Ajout de timedelta

from impacket.ldap.ldaptypes import LDAP_SID, SR_SECURITY_DESCRIPTOR, ACE, ACL, ACCESS_MASK
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACCESS_ALLOWED_OBJECT_ACE
try:
    from impacket.ldap.ldaptypes import OBJECT_TYPE_MAP
except ImportError:
    OBJECT_TYPE_MAP = {} 
    logging.warning("impacket.ldap.ldaptypes.OBJECT_TYPE_MAP not found. Extended rights name resolution will be limited.")

from src.adws import ADWSConnect, NTLMAuth
from src.soap_templates import NAMESPACES

# --- CONSTANTES ---
SOAPHOUND_LDAP_PROPERTIES = sorted(list(set([
    "objectSid", "objectGUID", "distinguishedName", "sAMAccountName", "name", "cn",
    "objectClass", "primaryGroupID", "userAccountControl", "lastLogonTimestamp",
    "pwdLastSet", "lastLogon", "whenCreated", "servicePrincipalName", "description",
    "operatingSystem", "sIDHistory", "nTSecurityDescriptor", "displayName", "title",
    "homeDirectory", "mail", "scriptPath", "adminCount", "member", "memberOf",
    "msDS-Behavior-Version", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "ms-MCS-AdmPwdExpirationTime", "dNSHostName", "gPCFileSysPath", "gPLink", "gPOptions",
    "trustAttributes", "trustDirection", "trustPartner", "flatName", "securityIdentifier",
    "instanceType", "whenChanged",
    "certificateTemplates", "cACertificate", "flags", 
    "msPKI-RA-Application-Policies", "msPKI-Certificate-Application-Policy",
    "msPKI-Minimal-Key-Size", "msPKI-Certificate-Name-Flag", 
    "msPKI-Enrollment-Flag", "msPKI-Private-Key-Flag", 
    "pKIExtendedKeyUsage", "pKIExpirationPeriod", "pKIOverlapPeriod",
    "msPKI-Cert-Template-OID", "revision", "pKIKeyUsage",
])))

SOAPHOUND_OBJECT_CLASS_MAPPING = { 
    "user": 0, "computer": 1, "group": 2, "groupPolicyContainer": 3,
    "domainDNS": 4, "domain": 4, "organizationalUnit": 5, 
    "container": 6, # Ajout explicite pour le cache
    "rpcContainer": 6, # Exemple d'autre type de conteneur
    "builtinDomain": 7, "foreignSecurityPrincipal": 2,
    "certificationAuthority": 8, "pKIEnrollmentService": 8, 
    "pKICertificateTemplate": 9,
}
SOAPHOUND_OBJECT_CLASS_PRIORITY = [ 
    "computer", "user", "group", "foreignSecurityPrincipal", "groupPolicyContainer",
    "pKICertificateTemplate", "certificationAuthority", "pKIEnrollmentService",
    "organizationalUnit", "domainDNS", "domain", 
    "container", "rpcContainer", # Ajoutés ici
    "builtinDomain"
]

EXTENDED_RIGHTS_GUID_MAP = {
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "GetChanges", 
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "GetChangesAll", 
    "89e95b76-444d-4c62-991a-0facbeda640c": "GetChangesInFilteredSet", 
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "DS-Control-Access", 
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll", 
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "AutoEnroll", 
    "9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Validated-Write-ServicePrincipalName",
    "e45795b2-9455-11d1-aebd-0000f80367c1": "DS-Validated-Write-DnsHostName",
}
for name, guid_bytes in OBJECT_TYPE_MAP.items():
    try:
        guid_str = str(UUID(bytes_le=guid_bytes)).lower()
        if guid_str not in EXTENDED_RIGHTS_GUID_MAP:
            EXTENDED_RIGHTS_GUID_MAP[guid_str] = name.replace('_', '-').capitalize()
    except: pass 

KNOWN_BINARY_ADWS_ATTRIBUTES = ["objectsid", "objectguid", "ntsecuritydescriptor", "sidhistory", "cacertificate", "pkioverlapperiod", "pkiexpirationperiod"]

OID_MAP = {
    "2.5.29.37.0": "Any Purpose", "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.2": "Client Authentication", "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent", "1.3.6.1.4.1.311.20.2.2": "Smartcard Logon",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System", "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
}

# --- FONCTION DE COLLECTE ADWS ---
def pull_all_ad_objects(ip: str, domain: str, username: str, auth: NTLMAuth, query: str, attributes: list, base_dn_override: str = None):
    # ... (pull_all_ad_objects inchangée par rapport à ma réponse précédente)
    logging.info(f"Collecting AD objects from {domain} via ADWS. Query: '{query}'. Base DN Override: {base_dn_override}")
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    all_pulled_items = []
    
    default_domain_root_dn = "DC=" + ",DC=".join(domain.split('.'))
    effective_base_dn = base_dn_override if base_dn_override else default_domain_root_dn

    # La modification pour utiliser effective_base_dn doit être faite dans ADWSConnect._query_enumeration
    # en lui permettant de prendre un `baseobj` en paramètre.
    # Pour l'instant, pull_client.pull utilisera le baseobj dérivé de self._domain.
    # Si vous avez adapté ADWSConnect.pull pour prendre un base_dn, utilisez-le ici.
    # Sinon, pour les requêtes sur CN=Configuration, il faut une instance ADWSConnect
    # où `domain` est effectivement la chaîne pour la partition de configuration.
    
    # Simuler un appel qui pourrait prendre un base_dn pour la démonstration
    # (votre ADWSConnect.pull actuel ne le fait pas, il dérive de self._domain)
    # logging.info(f"ADWSConnect.pull will use internal base_dn from domain '{domain}'. If '{effective_base_dn}' is different, adapt ADWSConnect.")

    try:
        pull_et = pull_client.pull(query=query, attributes=attributes) 

        for items_node in pull_et.findall(".//wsen:Items", namespaces=NAMESPACES):
            for item_elem in items_node.findall("./*", namespaces=NAMESPACES):
                obj_data = {}
                for attr_name_original_case in attributes:
                    attr_name_lower = attr_name_original_case.lower()
                    
                    attr_elems = item_elem.findall(f".//addata:{attr_name_original_case}/ad:value", namespaces=NAMESPACES)
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
                                else:
                                     values.append(val_elem.text)
                            else:
                                values.append(val_elem.text)
                        if values:
                            obj_data[attr_name_original_case] = values[0] if len(values) == 1 else values
                
                if 'distinguishedName' not in obj_data:
                    dn_elem = item_elem.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
                    if dn_elem is not None and dn_elem.text is not None: obj_data['distinguishedName'] = dn_elem.text
                
                if 'objectClass' not in obj_data:
                    oc_val = [oc.text for oc in item_elem.findall(".//addata:objectClass/ad:value", namespaces=NAMESPACES) if oc.text]
                    if oc_val: obj_data['objectClass'] = oc_val

                if obj_data.get('distinguishedName'):
                    all_pulled_items.append(obj_data)

    except Exception as e:
        logging.error(f"Error during ADWS object collection with query '{query}': {e}", exc_info=True)
        return {"objects": [], "domain_root_dn": default_domain_root_dn, "effective_base_dn_used": effective_base_dn }

    logging.info(f"Collected {len(all_pulled_items)} objects using query '{query}' (Base DN target: {effective_base_dn}).")
    return {"objects": all_pulled_items, "domain_root_dn": default_domain_root_dn, "effective_base_dn_used": effective_base_dn }

# --- FONCTIONS POUR LE CACHE SOAPHOUND (`--cache`) ---
# ... (get_soaphound_type_id, _generate_individual_caches, create_and_combine_soaphound_cache restent inchangées)
def get_soaphound_type_id(dn, object_classes, object_sid_str, domain_root_dn):
    if not isinstance(object_classes, list): object_classes = [object_classes]
    object_classes_lower = [str(oc).lower() for oc in object_classes]

    if object_sid_str == "S-1-5-32": return SOAPHOUND_OBJECT_CLASS_MAPPING.get("builtinDomain", 7)
    if object_sid_str == "S-1-5-17": return SOAPHOUND_OBJECT_CLASS_MAPPING.get("group", 2)
    if dn and domain_root_dn and dn.lower() == domain_root_dn.lower(): return SOAPHOUND_OBJECT_CLASS_MAPPING.get("domainDNS", 4)

    for oc_priority in SOAPHOUND_OBJECT_CLASS_PRIORITY:
        if oc_priority in object_classes_lower:
            type_id = SOAPHOUND_OBJECT_CLASS_MAPPING.get(oc_priority)
            if type_id is not None: return type_id
    if dn:
        if dn.lower().startswith("ou="): return SOAPHOUND_OBJECT_CLASS_MAPPING.get("organizationalUnit", 5)
        # elif dn.lower().startswith("cn="): return SOAPHOUND_OBJECT_CLASS_MAPPING.get("container", 6) # Trop générique
    # Si c'est 'container' explicitement et pas un autre type plus spécifique.
    if "container" in object_classes_lower:
        return SOAPHOUND_OBJECT_CLASS_MAPPING.get("container", 6)
    return SOAPHOUND_OBJECT_CLASS_MAPPING.get("container", 6) # Fallback


def _generate_individual_caches(all_pulled_items, domain_root_dn):
    logging.info("Generating individual cache dictionaries in memory for SOAPHound...")
    id_to_type_cache = {}
    value_to_id_cache = {} 

    for obj in all_pulled_items:
        dn = obj.get('distinguishedName')
        if not dn: continue

        raw_sid_bytes = obj.get('objectSid') 
        raw_guid_bytes = obj.get('objectGUID') 
        object_classes = obj.get('objectClass', [])

        sid_str, guid_str = None, None
        if isinstance(raw_sid_bytes, bytes): 
            try: sid_str = LDAP_SID(raw_sid_bytes).formatCanonical()
            except Exception as e: logging.debug(f"Cache: Could not format SID for {dn}: {e}")
        elif raw_sid_bytes: 
             logging.warning(f"Cache: SID for {dn} is string, not bytes: {raw_sid_bytes}")


        if isinstance(raw_guid_bytes, bytes): 
            try: guid_str = str(UUID(bytes_le=raw_guid_bytes))
            except Exception as e: logging.debug(f"Cache: Could not format GUID for {dn}: {e}")
        elif raw_guid_bytes:
             logging.warning(f"Cache: GUID for {dn} is string, not bytes: {raw_guid_bytes}")
        
        primary_id = sid_str if sid_str else guid_str
        if not primary_id: continue

        id_to_type_cache[primary_id] = get_soaphound_type_id(dn, object_classes, sid_str, domain_root_dn)
        value_to_id_cache[unicodedata.normalize('NFKC', dn).upper()] = primary_id
    
    logging.info(f"Generated {len(id_to_type_cache)} IdToType mappings and {len(value_to_id_cache)} ValueToId mappings.")
    return id_to_type_cache, value_to_id_cache

def create_and_combine_soaphound_cache(all_pulled_items, domain_root_dn, output_dir="."):
    id_to_type_path = os.path.join(output_dir, "IdToTypeCache.json") # SOAPHound ne génère pas ceux-ci par défaut
    value_to_id_path = os.path.join(output_dir, "ValueToIdCache.json") # SOAPHound ne génère pas ceux-ci par défaut
    combined_output_path = os.path.join(output_dir, "CombinedCache.json") 
    logging.info(f"Initiating SOAPHound cache generation...")

    id_to_type_dict, value_to_id_dict = _generate_individual_caches(all_pulled_items, domain_root_dn)

    if not id_to_type_dict or not value_to_id_dict:
        logging.error("Failed to generate individual cache dictionaries. Combined cache not created.")
        return

    try:
        # Pour correspondre à SOAPHound, on ne génère que CombinedCache.json
        # with open(id_to_type_path, "w", encoding="utf-8") as f: json.dump(id_to_type_dict, f, indent=2)
        # logging.info(f"IdToTypeCache.json saved to {id_to_type_path}")
        # with open(value_to_id_path, "w", encoding="utf-8") as f: json.dump(value_to_id_dict, f, indent=2)
        # logging.info(f"ValueToIdCache.json saved to {value_to_id_path}")
        
        combined_data = {"IdToTypeCache": id_to_type_dict, "ValueToIdCache": value_to_id_dict}
        with open(combined_output_path, 'w', encoding='utf-8') as f: json.dump(combined_data, f, indent=2) # SOAPHound n'utilise pas ensure_ascii=False par défaut
        logging.info(f"CombinedCache.json saved to {combined_output_path}")
    except IOError as e:
        logging.error(f"Error writing cache files: {e}")

# --- TRAITEMENT POUR BLOODHOUND (AMÉLIORÉ) ---

def _ldap_datetime_to_epoch(ldap_timestamp_str):
    if not ldap_timestamp_str or str(ldap_timestamp_str) in ['0', '9223372036854775807', '-1']:
        return 0 
    try:
        if isinstance(ldap_timestamp_str, str) and '.' in ldap_timestamp_str and ldap_timestamp_str.endswith('Z'):
            dt_obj = datetime.strptime(ldap_timestamp_str, "%Y%m%d%H%M%S.%fZ").replace(tzinfo=timezone.utc)
        else: 
            ft_int = int(ldap_timestamp_str)
            # FILETIME est en intervalles de 100ns depuis 1er Jan 1601 UTC
            # Python datetime.timestamp() est epoch Unix (secondes depuis 1er Jan 1970 UTC)
            # Différence entre 1601 et 1970 en secondes: 11644473600
            # Conversion de 100ns en secondes: / 10_000_000
            seconds_since_1601 = ft_int / 10000000.0
            dt_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
            dt_obj = dt_1601 + timedelta(seconds=seconds_since_1601)
        return int(dt_obj.timestamp())
    except Exception as e:
        logging.debug(f"Error converting timestamp '{ldap_timestamp_str}': {e}")
        return 0

def _parse_pki_flags(flag_value_str, flag_enum_map):
    parsed_flags = []
    if flag_value_str is None: return None
    try:
        val = int(flag_value_str)
        for flag_name, flag_bit in flag_enum_map.items():
            if val & flag_bit:
                parsed_flags.append(flag_name) # SOAPHound C# garde les noms d'enum
    except (ValueError, TypeError) as e:
        logging.warning(f"Could not parse PKI flag value '{flag_value_str}': {e}")
    return parsed_flags if parsed_flags else None

MSPKI_CERTIFICATE_NAME_FLAG_MAP = {
    "ENROLLEE_SUPPLIES_SUBJECT": 0x1, "ADD_EMAIL": 0x2, "ADD_OBJ_GUID": 0x4,
    "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME": 0x8, "ADD_DIRECTORY_PATH": 0x100,
    "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME": 0x10000, "SUBJECT_ALT_REQUIRE_DOMAIN_DNS": 0x400000,
    "SUBJECT_ALT_REQUIRE_SPN": 0x800000, "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID": 0x1000000,
    "SUBJECT_ALT_REQUIRE_UPN": 0x2000000, "SUBJECT_ALT_REQUIRE_EMAIL": 0x4000000,
    "SUBJECT_ALT_REQUIRE_DNS": 0x8000000, "SUBJECT_REQUIRE_DNS_AS_CN": 0x10000000,
    "SUBJECT_REQUIRE_EMAIL": 0x20000000, "SUBJECT_REQUIRE_COMMON_NAME": 0x40000000,
    "SUBJECT_REQUIRE_DIRECTORY_PATH": 0x80000000,
}
MSPKI_ENROLLMENT_FLAG_MAP = {
    "INCLUDE_SYMMETRIC_ALGORITHMS": 0x1, "PEND_ALL_REQUESTS": 0x2,
    "PUBLISH_TO_KRA_CONTAINER": 0x4, "PUBLISH_TO_DS": 0x8,
    "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE": 0x10, "AUTO_ENROLLMENT": 0x20,
    "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT": 0x40, "DOMAIN_AUTHENTICATION_NOT_REQUIRED": 0x80, # CT_FLAG_...
    "USER_INTERACTION_REQUIRED": 0x100, "ADD_TEMPLATE_NAME": 0x200,
    "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE": 0x400, "ALLOW_ENROLL_ON_BEHALF_OF": 0x800,
    "ADD_OCSP_NOCHECK": 0x1000, # ... (Compléter depuis Enums/PKI.cs)
}
MSPKI_PRIVATE_KEY_FLAG_MAP = { # masque 0x00FFFFFF appliqué par SOAPHound
    "REQUIRE_PRIVATE_KEY_ARCHIVAL": 0x1, "EXPORTABLE_KEY": 0x10,
    "STRONG_KEY_PROTECTION_REQUIRED": 0x20, "REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM": 0x40,
    "REQUIRE_SAME_KEY_RENEWAL": 0x80, "USE_LEGACY_PROVIDER": 0x100,
    # ... (Compléter depuis Enums/PKI.cs)
}


def _parse_aces(ntsd_bytes, sid_to_type_map, current_object_sid, object_type_label_for_ace="Base"):
    # ... (fonction _parse_aces comme précédemment, mais s'assurer que object_type_label_for_ace est passé)
    aces_list = []
    if not ntsd_bytes or not isinstance(ntsd_bytes, bytes): return aces_list
    try:
        sd = SR_SECURITY_DESCRIPTOR(data=ntsd_bytes)
        if sd['DaclPresent'] and sd['Dacl'] and hasattr(sd['Dacl'], 'aces'):
            for ace_raw in sd['Dacl'].aces:
                ace_obj = ace_raw['Ace']
                principal_sid_obj = LDAP_SID(ace_obj['Sid'])
                principal_sid = principal_sid_obj.formatCanonical()
                # Utiliser object_type_label_for_ace pour le type par défaut si le SID n'est pas dans la map
                principal_type_label = _resolve_principal_type(principal_sid, sid_to_type_map, object_type_label_for_ace).capitalize()
                
                ace_mask = int(ace_obj['Mask']['Mask'])
                right_name = "Unknown" 
                is_inherited = bool(ace_raw['AceFlags'] & ACE.INHERITED_ACE)

                if ace_raw['AceType'] in [ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE] and ace_obj['ObjectType']: 
                    guid_str = str(UUID(bytes_le=ace_obj['ObjectType'])).lower()
                    right_name = EXTENDED_RIGHTS_GUID_MAP.get(guid_str, f"ControlAccess-{guid_str}")
                elif ace_mask == 0xf01ff or ace_mask == 983551 or ace_mask == 0x10000000 or ace_mask == 2032127: right_name = "GenericAll" 
                elif ace_mask & 0x00040000: right_name = "WriteDacl" 
                elif ace_mask & 0x00020000: right_name = "WriteOwner"
                # Mappages plus spécifiques basés sur SOAPHound ACLProcessor.cs (simplifié)
                elif object_type_label_for_ace == "Domain":
                    if right_name == "ControlAccess-1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": right_name = "GetChanges"
                    elif right_name == "ControlAccess-1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": right_name = "GetChangesAll"
                    # ... etc pour les autres droits spécifiques au domaine
                elif object_type_label_for_ace == "User":
                     if right_name == "ControlAccess-00299570-246d-11d0-a768-00aa006e0529": right_name = "ForceChangePassword"
                # (Les droits sur propriétés comme WriteSPN, WriteMember sont plus complexes à mapper uniquement avec le masque générique)

                if ace_raw['AceType'] == ACCESS_ALLOWED_ACE.ACE_TYPE or ace_raw['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                    if principal_sid == current_object_sid and right_name not in ["GenericAll", "WriteDacl", "WriteOwner"]:
                        continue 
                    aces_list.append({
                        "PrincipalSID": principal_sid, "PrincipalType": principal_type_label,
                        "RightName": right_name, "IsInherited": is_inherited, "AceType": "Allowed"
                    })
    except Exception as e:
        logging.debug(f"Failed to parse NTSD for {current_object_sid}: {e}", exc_info=False)
    return aces_list


def process_bloodhound_data(all_collected_items: list, domain_name: str, domain_root_dn: str):
    logging.info(f"Processing {len(all_collected_items)} items for BloodHound for domain: {domain_name}")
    
    users_bh, computers_bh, groups_bh, domains_bh, ous_bh, gpos_bh, cas_bh, cert_templates_bh, containers_bh = [], [], [], [], [], [], [], [], []

    sid_to_type_map = {}; dn_to_sid_map = {}; guid_to_sid_map = {}
    # Première passe pour construire les maps d'identifiants
    for item in all_collected_items:
        sid_bytes = item.get('objectSid'); guid_bytes = item.get('objectGUID')
        oc_list_raw = item.get('objectClass', []); dn = item.get('distinguishedName')
        oc_list = [str(oc).lower() for oc in oc_list_raw] if isinstance(oc_list_raw, list) else [str(oc_list_raw).lower()]
        
        sid_str, guid_str = None, None
        if isinstance(sid_bytes, bytes):
            try: sid_str = LDAP_SID(sid_bytes).formatCanonical()
            except: pass
        if isinstance(guid_bytes, bytes):
            try: guid_str = str(UUID(bytes_le=guid_bytes))
            except: pass
        
        if dn:
            dn_upper = dn.upper()
            if sid_str: dn_to_sid_map[dn_upper] = sid_str
            elif guid_str: dn_to_sid_map[dn_upper] = guid_str 

        current_id_for_map = sid_str or guid_str
        if current_id_for_map:
            obj_label = "Base" # Default
            if "computer" in oc_list: obj_label = "Computer"
            elif "user" in oc_list: obj_label = "User"
            elif "group" in oc_list: obj_label = "Group"
            elif "domain" in oc_list or "domaindns" in oc_list: obj_label = "Domain"
            elif "organizationalunit" in oc_list: obj_label = "OU"; guid_to_sid_map[guid_str] = guid_str
            elif "grouppolicycontainer" in oc_list: obj_label = "GPO"; guid_to_sid_map[guid_str] = guid_str
            elif "certificationauthority" in oc_list or "pkienrollmentservice" in oc_list : obj_label = "CA"; guid_to_sid_map[guid_str] = guid_str
            elif "pkicertificatetemplate" in oc_list: obj_label = "CertTemplate"; guid_to_sid_map[guid_str] = guid_str
            elif "container" in oc_list: obj_label = "Container"; guid_to_sid_map[guid_str] = guid_str # Conteneurs utilisent GUID
            elif "trusteddomain" in oc_list: obj_label = "Domain" # Pour les trusts
            
            sid_to_type_map[current_id_for_map] = obj_label
            if guid_str and sid_str and guid_str not in sid_to_type_map: # Assurer le mapping du GUID aussi
                 sid_to_type_map[guid_str] = obj_label


    # Traitement de l'objet Domaine principal
    domain_sid_str, domain_guid_str = "", ""
    trusts_for_domain_node = [] 
    # ... (Logique de recherche et création du nœud domaine principal comme dans la réponse précédente,
    #      en s'assurant de bien peupler domain_sid_str et domain_guid_str.
    #      La partie Trusts sera remplie par l'itération ci-dessous sur les objets trustedDomain)

    # Itération principale pour traiter tous les objets
    for item in all_collected_items:
        oc_list_lower = [str(oc).lower() for oc in item.get("objectClass", [])]
        dn = item.get("distinguishedName", "")
        if not dn: continue

        sid_bytes = item.get('objectSid'); guid_bytes = item.get('objectGUID')
        sid_str, guid_str = "", ""
        if isinstance(sid_bytes, bytes): 
            try: sid_str = LDAP_SID(sid_bytes).formatCanonical()
            except: pass
        if isinstance(guid_bytes, bytes):
            try: guid_str = str(UUID(bytes_le=guid_bytes))
            except: pass
        
        # Déterminer le type et l'ObjectIdentifier
        obj_type_bh, object_identifier = None, None
        # ... (Logique de détermination de obj_type_bh et object_identifier comme avant,
        #      utilisant sid_str pour User/Computer/Group/Domain(trust) et guid_str pour OU/GPO/CA/CertTemplate/Container)
        
        # Filtres pour certains conteneurs (inspiré de SOAPHound IsDistinguishedNameFiltered)
        dn_upper_for_filter = dn.upper()
        if "CN=PROGRAM DATA,DC=" in dn_upper_for_filter or \
           "CN=SYSTEM,DC=" in dn_upper_for_filter or \
           (dn_upper_for_filter.startswith("CN=DOMAINUPDATES,CN=SYSTEM,")) or \
           (dn_upper_for_filter.startswith(("CN=USER,", "CN=MACHINE,")) and ",CN=POLICIES,CN=SYSTEM," in dn_upper_for_filter):
            logging.debug(f"Skipping filtered DN: {dn}")
            continue

        # ... (Suite de la logique pour chaque type d'objet : User, Computer, Group, OU, GPO, CA, CertTemplate, Container, TrustedDomain)
        # ... (S'assurer que les propriétés, ACEs, relations sont bien remplies pour chaque type)
        # ... (Pour les trusts, les ajouter à trusts_for_domain_node)

        # Exemple pour un conteneur
        if "container" in oc_list_lower and not obj_type_bh : # Fallback si pas un type plus spécifique
            obj_type_bh = "Container"
            object_identifier = guid_str # Les conteneurs utilisent leur GUID
        
        if not object_identifier and obj_type_bh != "Domain": # Les domaines (trusts) peuvent avoir SID
             # Si c'est un conteneur sans GUID (rare mais possible pour certains CN built-in), on pourrait utiliser le DN
             if obj_type_bh == "Container" and dn: object_identifier = dn.upper() # Fallback à DN pour certains conteneurs
             else:
                logging.debug(f"Skipping object {dn} with no suitable ObjectIdentifier for type {obj_type_bh}")
                continue
        
        props = {"domain": domain_name.upper(), "distinguishedname": dn.upper()}
        if domain_sid_str: props["domainsid"] = domain_sid_str
        if guid_str: props["objectguid"] = guid_str

        # Nommage
        name_prop = item.get("name") or item.get("cn")
        if obj_type_bh in ["User", "Group"] and item.get("sAMAccountName"):
            props["samaccountname"] = item.get("sAMAccountName")
            props["name"] = f"{item.get('sAMAccountName').upper()}@{domain_name.upper()}"
        elif obj_type_bh == "Computer" and item.get("dNSHostName"):
            props["name"] = item.get("dNSHostName").upper()
            props["dnshostname"] = item.get("dNSHostName")
            if item.get("sAMAccountName"): props["samaccountname"] = item.get("sAMAccountName")
        elif name_prop:
            props["name"] = name_prop.upper() # Pour Domain, OU, GPO, CA, CertTemplate, Container
        else:
            props["name"] = dn.upper() # Fallback

        # Propriétés communes
        # ... (adminCount, description, whencreated, lastlogon, etc. comme avant) ...

        bh_node = {
            "ObjectIdentifier": object_identifier, "Name": props.get("name"),
            "ObjectType": obj_type_bh, "IsDeleted": False, "IsACLProtected": False, # Suppositions
            "Properties": props,
            "Aces": _parse_aces(item.get("nTSecurityDescriptor"), sid_to_type_map, object_identifier, obj_type_bh),
        }

        # Logique spécifique par type...
        if obj_type_bh == "User": # ... remplissage ...
            users_bh.append(bh_node)
        elif obj_type_bh == "Computer": # ... remplissage ...
            computers_bh.append(bh_node)
        # ... autres types ...
        elif obj_type_bh == "Container":
            # Les conteneurs ont des propriétés basiques. Highvalue est rarement True.
            props["highvalue"] = ("CN=DOMAIN CONTROLLERS" in dn.upper()) # Exemple
            containers_bh.append(bh_node)
        elif obj_type_bh == "Domain" and "trusteddomain" in oc_list_lower:
             # Traitement des trusts (déjà esquissé plus haut)
             # ...
             pass # Ne pas ajouter comme un nœud 'domain' séparé ici, mais à 'trusts_for_domain_node'


    # Finaliser l'objet domaine principal avec les trusts et ChildObjects
    if domains_bh:
        domains_bh[0]["Trusts"] = trusts_for_domain_node
        # Peupler ChildObjects pour le domaine (objets directement sous le DN du domaine)
        child_objects_domain = []
        domain_dn_upper = domain_root_dn.upper()
        for obj_dn_upper, obj_sid in dn_to_sid_map.items():
            # Un enfant est un niveau plus profond et commence par le DN du parent
            if obj_dn_upper.endswith("," + domain_dn_upper) and \
               obj_dn_upper.count(',') == domain_dn_upper.count(',') + 1:
                obj_type = sid_to_type_map.get(obj_sid, "Base").capitalize()
                child_objects_domain.append({"ObjectIdentifier": obj_sid, "ObjectType": obj_type})
        domains_bh[0]["ChildObjects"] = child_objects_domain
    
    # Écriture des fichiers
    # ... (write_json_file comme avant, ajouter un appel pour containers_bh) ...
    # ... (SOAPHound met CA et Templates dans gpos.json. Je vais faire des fichiers séparés pour plus de clarté.)
    output_base_name = f"soapyhound-{domain_name.lower()}"
    def write_json_file(data, filename_suffix, data_type_meta, version=5):
        # ... (fonction write_json_file inchangée) ...
        if not data: logging.info(f"No data for {data_type_meta}, skipping file generation."); return
        file_path = os.path.join(".", f"{output_base_name}_{filename_suffix}.json")
        output_data = {"data": data, "meta": {"methods": 0, "type": data_type_meta, "version": version, "count": len(data)}}
        try:
            with open(file_path, 'w', encoding='utf-8') as f: json.dump(output_data, f, ensure_ascii=False, indent=2)
            logging.info(f"BloodHound data written to {file_path} ({len(data)} {data_type_meta}).")
        except IOError as e: logging.error(f"Error writing to file {file_path}: {e}")

    write_json_file(users_bh, "users", "users")
    write_json_file(computers_bh, "computers", "computers")
    write_json_file(groups_bh, "groups", "groups")
    write_json_file(domains_bh, "domains", "domains")
    write_json_file(ous_bh, "ous", "ous")
    write_json_file(gpos_bh, "gpos", "gpos")
    write_json_file(cas_bh, "cas", "cas") 
    write_json_file(cert_templates_bh, "certtemplates", "certificatetemplates")
    write_json_file(containers_bh, "containers", "containers")

    logging.info("BloodHound data processing complete.")