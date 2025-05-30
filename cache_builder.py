import argparse
import logging
import sys
import json
import io
import unicodedata
from enum import Enum
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.ldap.ldaptypes import (
    LDAP_SID,
)

from src.adws import ADWSConnect, NTLMAuth, WELL_KNOWN_SIDS

class Label(Enum):
    USER = 0
    COMPUTER = 1
    GROUP = 2
    GPO = 6
    DOMAIN = 3
    OU = 4
    CONTAINER = 5
    BASE = 7
    CA = 8

# Définition explicite des correspondances Label -> Integer (aligné sur SOAPHound)
LABEL_TO_INT = {
    Label.USER: 0,
    Label.COMPUTER: 1,
    Label.GROUP: 2,
    Label.DOMAIN: 3,
    Label.OU: 4,
    Label.CONTAINER: 5,
    Label.GPO: 6,
    Label.BASE: 7,
    Label.CA: 8,
}

# Mapping précis des SIDs bien connus aux Labels (basé sur le code SOAPHound fourni)
WELL_KNOWN_SID_TO_LABEL = {
    "S-1-0": Label.USER,
    "S-1-0-0": Label.USER,
    "S-1-1": Label.USER,
    "S-1-1-0": Label.GROUP,
    "S-1-2": Label.USER,
    "S-1-2-0": Label.GROUP,
    "S-1-2-1": Label.GROUP,
    "S-1-3": Label.USER,
    "S-1-3-0": Label.USER,
    "S-1-3-1": Label.GROUP,
    "S-1-3-2": Label.COMPUTER,
    "S-1-3-3": Label.COMPUTER,
    "S-1-3-4": Label.GROUP,
    "S-1-4": Label.USER,
    "S-1-5": Label.USER,
    "S-1-5-1": Label.GROUP,
    "S-1-5-2": Label.GROUP,
    "S-1-5-3": Label.GROUP,
    "S-1-5-4": Label.GROUP,
    "S-1-5-6": Label.GROUP,
    "S-1-5-7": Label.GROUP,
    "S-1-5-8": Label.GROUP,
    "S-1-5-9": Label.GROUP,
    "S-1-5-10": Label.USER,
    "S-1-5-11": Label.GROUP,
    "S-1-5-12": Label.GROUP,
    "S-1-5-13": Label.GROUP,
    "S-1-5-14": Label.GROUP,
    "S-1-5-15": Label.GROUP,
    "S-1-5-17": Label.GROUP,
    "S-1-5-18": Label.USER,
    "S-1-5-19": Label.USER,
    "S-1-5-20": Label.USER,
    "S-1-5-113": Label.USER,
    "S-1-5-114": Label.USER,
    "S-1-5-80-0": Label.GROUP,
    "S-1-5-32-544": Label.GROUP,
    "S-1-5-32-545": Label.GROUP,
    "S-1-5-32-546": Label.GROUP,
    "S-1-5-32-547": Label.GROUP,
    "S-1-5-32-548": Label.GROUP,
    "S-1-5-32-549": Label.GROUP,
    "S-1-5-32-550": Label.GROUP,
    "S-1-5-32-551": Label.GROUP,
    "S-1-5-32-552": Label.GROUP,
    "S-1-5-32-554": Label.GROUP,
    "S-1-5-32-555": Label.GROUP,
    "S-1-5-32-556": Label.GROUP,
    "S-1-5-32-557": Label.GROUP,
    "S-1-5-32-558": Label.GROUP,
    "S-1-5-32-559": Label.GROUP,
    "S-1-5-32-560": Label.GROUP,
    "S-1-5-32-561": Label.GROUP,
    "S-1-5-32-562": Label.GROUP,
    "S-1-5-32-568": Label.GROUP,
    "S-1-5-32-569": Label.GROUP,
    "S-1-5-32-573": Label.GROUP,
    "S-1-5-32-574": Label.GROUP,
    "S-1-5-32-575": Label.GROUP,
    "S-1-5-32-576": Label.GROUP,
    "S-1-5-32-577": Label.GROUP,
    "S-1-5-32-578": Label.GROUP,
    "S-1-5-32-579": Label.GROUP,
    "S-1-5-32-580": Label.GROUP,
}

def class_to_label(object_class):
    """
    Mappe la classe d'objet LDAP à un Label (aligné sur SOAPHound).
    """
    if "group" in object_class:
        return Label.GROUP
    elif "user" in object_class or "msds-managedserviceaccount" in object_class or "msds-groupmanagedserviceaccount" in object_class:
        return Label.USER
    elif "computer" in object_class:
        return Label.COMPUTER
    elif "grouppolicycontainer" in object_class:
        return Label.GPO
    elif "container" in object_class:
        return Label.CONTAINER
    elif "organizationalunit" in object_class:
        return Label.OU
    elif "domain" in object_class or "domaindns" in object_class or "trusteddomain" in object_class:
        return Label.DOMAIN
    elif "certificationauthority" in [oc.lower() for oc in object_class]: # Gestion pour CA (peut apparaître dans objectClass)
        return Label.CA
    return Label.BASE

def build_cache(target, hashes=None, kerberos=False, no_pass=False, ldap_query=["(!soaphound=*)"], attributes=["objectSid", "objectGUID", "distinguishedName", "objectClass", "objectCategory"]):
    """
    Récupère les objets AD et construit les caches ValueToIdCache et IdToTypeCache.
    """
    domain, username, password, address = parse_target(target)
    if not domain:
        logging.error("Please specify a domain.")
        return None

    auth = NTLMAuth(password=password, hashes=hashes)
    client = ADWSConnect.pull_client(
        ip=address,
        domain=domain,
        username=username,
        auth=auth,
    )

    value_to_id_cache = {}
    id_to_type_cache = {}

    # Capture de la sortie standard de adws.py
    old_stdout = sys.stdout
    sys.stdout = captured_stdout = io.StringIO()

    for query in ldap_query:
        if query:
            client.pull(query, attributes, print_incrementally=True)

    sys.stdout = old_stdout
    output = captured_stdout.getvalue()
    lines = output.splitlines()

    current_object = {}
    dn = None
    sid = None
    guid = None
    object_class_list = []
    object_category = ""

    for line in lines:
        line = line.strip()
        if line.startswith("[+] Object Found: "):
            dn = None
            sid = None
            guid = None
            object_class_list = []
            object_category = ""
        elif line.startswith("distinguishedName: "):
            dn = line.split("distinguishedName: ")[1].strip()
        elif line.startswith("objectSid: "):
            current_sid = line.split("objectSid: ")[1].strip()
            sid = current_sid.split("Well known sid:")[0].strip() if "Well known sid:" in current_sid else current_sid
        elif line.startswith("objectGUID: "):
            guid = line.split("objectGUID: ")[1].strip()
        elif line.startswith("objectClass: "):
            object_class_list = [oc.strip().lower() for oc in line.split("objectClass: ")[1].split(',')]
        elif line.startswith("objectCategory: "):
            object_category = line.split("objectCategory: ")[1].strip().lower()

        if dn and (sid or guid):
            identifier = sid if sid else guid
            normalized_dn = unicodedata.normalize('NFKC', dn)
            if normalized_dn not in value_to_id_cache:
                value_to_id_cache[normalized_dn] = identifier

            object_type = Label.BASE # Default
            if sid:
                if sid in WELL_KNOWN_SID_TO_LABEL:
                    object_type = WELL_KNOWN_SID_TO_LABEL[sid]
            elif object_class_list:
                object_type = class_to_label(object_class_list)
                if object_type == Label.BASE and object_category:
                    if "person" in object_category:
                        object_type = Label.USER
                    elif "group" in object_category:
                        object_type = Label.GROUP
                    elif "computer" in object_category:
                        object_type = Label.COMPUTER

            if identifier and identifier not in id_to_type_cache:
                id_to_type_cache[identifier] = LABEL_TO_INT.get(object_type, Label.BASE.value)

    return {"IdToTypeCache": id_to_type_cache, "ValueToIdCache": value_to_id_cache}

def run_cli():
    parser = argparse.ArgumentParser(
        description="Queries ADWS and builds a cache in JSON format."
    )
    parser.add_argument("target", action="store", help="[domain/][user[:password]@]<ip or hostname>")
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    parser.add_argument("--no-pass", action="store_true", help="don't ask for password (useful for -k)")
    parser.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    parser.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH", help="NTLM hashes")
    parser.add_argument("-output-file", action="store", metavar="OUTFILE", default="cache_soapy.json", help="Output filename for the cache (default: cache_soapy.json)")
    parser.add_argument("-ldap-query", action="append", metavar="QUERY", default=["(!soaphound=*)"], help="Custom LDAP query (default: '(!soaphound=*)')")
    parser.add_argument("-filter", action="store", metavar="ATTRIBUTE=VALUE", help="Filter based on an attribute value")
    parser.add_argument("-attributes", action="store", default="objectSid,objectGUID,distinguishedName,objectClass,objectCategory", help="Comma-separated attributes to retrieve")

    options = parser.parse_args()

    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.no_pass and options.hashes is None and not options.kerberos:
        logging.error("No credentials provided. Aborting...")
        sys.exit(1)

    target = parse_target(options.target)
    if not target:
        logging.error("Error parsing target address.")
        sys.exit(1)

    ldap_query = options.ldap_query
    if options.filter:
        try:
            attribute, value = options.filter.split("=", 1)
            ldap_query.append(f"({attribute}={value})")
        except ValueError:
            logging.error("Invalid filter format. Use ATTRIBUTE=VALUE")
            sys.exit(1)

    attributes = [attr.strip() for attr in options.attributes.split(',')]
    if "objectCategory" not in attributes:
        attributes.append("objectCategory")

    cache_data = build_cache(options.target, hashes=options.hashes, kerberos=options.kerberos, no_pass=options.no_pass, ldap_query=ldap_query, attributes=attributes)

    if cache_data:
        try:
            with open(options.output_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False, sort_keys=True)
            logging.info(f"Cache data written to: {options.output_file}")
        except Exception as e:
            logging.error(f"Error writing cache to file: {e}")

if __name__ == "__main__":
    logger.init()
    run_cli()