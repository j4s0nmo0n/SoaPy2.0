import json
import logging
import unicodedata
from base64 import b64decode
from uuid import UUID
import os

from impacket.ldap.ldaptypes import LDAP_SID

# Mapping objectClass to SOAPHound Type IDs
# VOS MAPPINGS MIS À JOUR
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
    "foreignSecurityPrincipal": 2, # <-- Ajouté pour mapper ForeignSecurityPrincipal à l'ID de groupe
}

# Priority order for determining SOAPHound type if an object has multiple objectClass values.
SOAPHOUND_OBJECT_CLASS_PRIORITY = [
    "computer",  # Déplacé avant "user"
    "user",
    "group",
    "foreignSecurityPrincipal", # Déplacé avant "container"
    "groupPolicyContainer",
    "organizationalUnit",
    "domainDNS",
    "container",
    "base",
    "CA",
]

def get_soaphound_type_id(dn, object_classes, object_sid, domain_root_dn):
    """
    Determines the SOAPHound type ID for an AD object based on objectClass and well-known SIDs.
    """
    # Cas spéciaux (SIDs bien connus) - PRIORITÉ LA PLUS HAUTE
    if object_sid == "S-1-5-32": # Builtin container
        return 7
    if object_sid == "S-1-5-17": # Service Logon Account (c'est un groupe)
        return 2

    # Cas spécial pour l'objet Domaine lui-même (base de recherche)
    if dn and domain_root_dn and dn.lower() == domain_root_dn.lower():
        return 4

    # Appliquer le mapping objectClass basé sur la priorité
    for oc_priority in SOAPHOUND_OBJECT_CLASS_PRIORITY:
        if oc_priority in object_classes:
            type_id = SOAPHOUND_OBJECT_CLASS_MAPPING.get(oc_priority)
            if type_id is not None:
                return type_id

    # Fallback pour les objets qui n'ont pas de mapping direct par objectClass
    if dn:
        if dn.startswith("OU="):
            return 5  # Assume OU si DN commence par OU
        elif dn.startswith("CN="):
            # Ceci est un fallback pour les conteneurs génériques
            return 6 # Assumer un container générique

    return 6 # Fallback par défaut à l'ID de conteneur générique si aucun type spécifique n'est déterminé


def generate_soaphound_caches(all_pulled_items, domain_root_dn, output_dir="."):
    """
    Generates IdToTypeCache.json, ValueToIdCache.json, and a combined cache.

    Args:
        all_pulled_items (list): List of dictionaries, each representing an AD object.
        domain_root_dn (str): The distinguishedName of the domain root.
        output_dir (str): Directory where the cache files will be saved.
    Returns:
        tuple: (id_to_type_cache_dict, value_to_id_cache_dict) if successful, else (None, None).
    """
    logging.info("Starting SOAPHound cache generation...")
    id_to_type_cache = {}
    value_to_id_cache = {}

    for obj in all_pulled_items:
        dn = obj.get('distinguishedName')
        raw_sid_b64 = obj.get('objectSid')
        raw_guid_b64 = obj.get('objectGUID')
        object_classes = obj.get('objectClass', [])

        if not dn or (not raw_sid_b64 and not raw_guid_b64):
            logging.debug(f"Skipping incomplete object for cache generation: {dn}")
            continue

        sid_canonical = None
        if raw_sid_b64:
            try:
                sid_obj = LDAP_SID(data=b64decode(raw_sid_b64))
                sid_canonical = sid_obj.formatCanonical()
            except Exception as e:
                logging.debug(f"Could not decode SID for {dn}: {e}. Raw: {raw_sid_b64}")

        guid_str = None
        if raw_guid_b64:
            try:
                guid_bytes_le = b64decode(raw_guid_b64)
                guid_str = str(UUID(bytes_le=guid_bytes_le))
            except Exception as e:
                logging.debug(f"Could not decode GUID for {dn}: {e}. Raw: {raw_guid_b64}")

        # Determine the primary identifier (SID preferred)
        primary_identifier = None
        if sid_canonical:
            primary_identifier = sid_canonical
        elif guid_str:
            primary_identifier = guid_str
        else:
            logging.warning(f"Object {dn} has neither SID nor GUID. Skipping for cache.")
            continue

        # Populate IdToTypeCache
        id_to_type_cache[primary_identifier] = get_soaphound_type_id(dn, object_classes, sid_canonical, domain_root_dn)

        # Populate ValueToIdCache
        value_to_id_cache[unicodedata.normalize('NFKC', dn)] = primary_identifier
        
        # Do NOT add GUID:SID mappings to ValueToIdCache based on previous request
        # if guid_str and guid_str != primary_identifier:
        #    value_to_id_cache[guid_str] = primary_identifier

    # Save IdToTypeCache.json
    id_to_type_path = os.path.join(output_dir, "IdToTypeCache.json")
    try:
        with open(id_to_type_path, "w", encoding="utf-8") as f:
            json.dump(id_to_type_cache, f, indent=2, ensure_ascii=False)
        logging.info(f"IdToTypeCache.json generated at {id_to_type_path}")
    except IOError as e:
        logging.error(f"Error writing IdToTypeCache.json: {e}")
        return None, None

    # Save ValueToIdCache.json
    value_to_id_path = os.path.join(output_dir, "ValueToIdCache.json")
    try:
        with open(value_to_id_path, "w", encoding="utf-8") as f:
            json.dump(value_to_id_cache, f, indent=2, ensure_ascii=False)
        logging.info(f"ValueToIdCache.json generated at {value_to_id_path}")
    except IOError as e:
        logging.error(f"Error writing ValueToIdCache.json: {e}")
        return None, None

    # Return the dictionaries for the combined cache step
    return id_to_type_cache, value_to_id_cache


def combine_generated_caches(id_to_type_cache_dict, value_to_id_cache_dict, output_path="CombinedCache.json"):
    """
    Combines the two generated cache dictionaries into a single JSON file
    with 'IdToTypeCache' and 'ValueToIdCache' as root keys.
    """
    if id_to_type_cache_dict is None or value_to_id_cache_dict is None:
        logging.error("Cannot combine caches: one or both input dictionaries are empty or None.")
        return

    combined_data = {
        "IdToTypeCache": id_to_type_cache_dict,
        "ValueToIdCache": value_to_id_cache_dict
    }

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(combined_data, f, indent=2, ensure_ascii=False)
        logging.info(f"Combined cache saved to {output_path}")
    except IOError as e:
        logging.error(f"Error writing combined cache to {output_path}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while saving the combined cache: {e}")