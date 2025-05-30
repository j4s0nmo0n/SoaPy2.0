import json
import logging
import unicodedata
from base64 import b64decode, b64encode
from uuid import UUID
import os

from impacket.ldap.ldaptypes import LDAP_SID

# Mapping objectClass to SOAPHound Type IDs
SOAPHOUND_OBJECT_CLASS_MAPPING = {
    "user": 0,
    "computer": 1,
    "group": 2,
    "grouppolicycontainer": 3,
    "domaindns": 4, 
    "organizationalunit": 5,
    "container": 6,
    "domain": 4, # Alias for domainDNS
    # "base": 7, # Moins critique pour la structure de base
    # "ca": 8, # Si vous avez des autorités de certification spécifiques à typer
    "foreignsecurityprincipal": 2,
}

SOAPHOUND_OBJECT_CLASS_PRIORITY = [
    "computer", "user", "group", "foreignsecurityprincipal",
    "grouppolicycontainer", "organizationalunit", "domaindns", "domain", "container",
]

def get_soaphound_type_id(dn, object_classes_raw, object_sid_str, domain_root_dn):
    if not isinstance(object_classes_raw, list):
        object_classes = [str(object_classes_raw).lower()]
    else:
        object_classes = [str(oc).lower() for oc in object_classes_raw]

    if object_sid_str == "S-1-5-32": return 7
    if object_sid_str == "S-1-5-17": return 2

    if dn and domain_root_dn and dn.lower() == domain_root_dn.lower():
        return SOAPHOUND_OBJECT_CLASS_MAPPING.get("domaindns", 4)

    for oc_priority in SOAPHOUND_OBJECT_CLASS_PRIORITY:
        if oc_priority in object_classes:
            type_id = SOAPHOUND_OBJECT_CLASS_MAPPING.get(oc_priority)
            if type_id is not None:
                return type_id
    
    if dn: # Fallbacks basés sur le DN
        dn_lower = dn.lower()
        if dn_lower.startswith("ou="): return SOAPHOUND_OBJECT_CLASS_MAPPING.get("organizationalunit", 5)
        if dn_lower.startswith("cn=policies,cn=system"): return SOAPHOUND_OBJECT_CLASS_MAPPING.get("grouppolicycontainer", 3)
        if dn_lower.startswith("cn="): return SOAPHOUND_OBJECT_CLASS_MAPPING.get("container", 6)
    return 6

def generate_soaphound_caches(all_pulled_items, domain_root_dn, output_dir="."):
    logging.info("Starting SOAPHound cache generation...")
    id_to_type_cache = {}
    value_to_id_cache = {}

    for obj in all_pulled_items:
        dn = obj.get('distinguishedName')
        raw_sid_b64 = obj.get('objectSid') 
        raw_guid_b64 = obj.get('objectGUID')
        object_classes = obj.get('objectClass', [])

        if not dn:
            logging.debug(f"CacheGen: Skipping object with no DN.")
            continue

        sid_canonical, guid_str = None, None
        if raw_sid_b64 and isinstance(raw_sid_b64, str): # Doit être une chaîne pour b64decode
            try:
                sid_obj = LDAP_SID(data=b64decode(raw_sid_b64))
                sid_canonical = sid_obj.formatCanonical()
            except Exception as e:
                logging.info(f"CacheGen: FAILED to decode SID for {dn} (Raw: '{raw_sid_b64[:30]}...'): {e}")
        elif not raw_sid_b64:
            logging.info(f"CacheGen: No 'objectSid' found or it's empty for {dn}.")
            
        if raw_guid_b64 and isinstance(raw_guid_b64, str): # Doit être une chaîne pour b64decode
            try:
                guid_bytes_le = b64decode(raw_guid_b64)
                guid_str = str(UUID(bytes_le=guid_bytes_le))
            except Exception as e:
                logging.info(f"CacheGen: FAILED to decode GUID for {dn} (Raw: '{raw_guid_b64[:30]}...'): {e}")
        elif not raw_guid_b64:
             logging.info(f"CacheGen: No 'objectGUID' found or it's empty for {dn}.")

        primary_identifier = sid_canonical if sid_canonical else guid_str
        if not primary_identifier:
            logging.warning(f"CacheGen: Object {dn} has neither valid SID nor GUID after attempting decode. Skipping.")
            continue

        id_to_type_cache[primary_identifier] = get_soaphound_type_id(dn, object_classes, sid_canonical, domain_root_dn)
        value_to_id_cache[unicodedata.normalize('NFKC', dn).upper()] = primary_identifier
        
    id_to_type_path = os.path.join(output_dir, "IdToTypeCache.json")
    try:
        with open(id_to_type_path, "w", encoding="utf-8") as f: json.dump(id_to_type_cache, f, indent=2, ensure_ascii=False)
        logging.info(f"IdToTypeCache.json generated at {id_to_type_path} ({len(id_to_type_cache)} entries)")
    except IOError as e: logging.error(f"Error writing IdToTypeCache.json: {e}"); return None, None

    value_to_id_path = os.path.join(output_dir, "ValueToIdCache.json")
    try:
        with open(value_to_id_path, "w", encoding="utf-8") as f: json.dump(value_to_id_cache, f, indent=2, ensure_ascii=False)
        logging.info(f"ValueToIdCache.json generated at {value_to_id_path} ({len(value_to_id_cache)} entries)")
    except IOError as e: logging.error(f"Error writing ValueToIdCache.json: {e}"); return None, None

    return id_to_type_cache, value_to_id_cache

def combine_generated_caches(id_to_type_cache_dict, value_to_id_cache_dict, output_path="CombinedCache.json"):
    if id_to_type_cache_dict is None or value_to_id_cache_dict is None:
        logging.error("Cannot combine caches: one or both input dictionaries are None.")
        return
    # Ne pas créer le fichier combiné s'il n'y a rien à y mettre
    if not id_to_type_cache_dict and not value_to_id_cache_dict:
        logging.warning("Input cache dictionaries are empty. CombinedCache will not be meaningful.")
        # On peut choisir de ne pas le créer ou de créer un fichier vide structuré.
        # Pour l'instant, on le crée même vide.
        
    combined_data = {"IdToTypeCache": id_to_type_cache_dict, "ValueToIdCache": value_to_id_cache_dict}
    try:
        with open(output_path, 'w', encoding='utf-8') as f: json.dump(combined_data, f, indent=2, ensure_ascii=False)
        logging.info(f"Combined cache saved to {output_path}")
    except IOError as e: logging.error(f"Error writing combined cache to {output_path}: {e}")

# --- AJOUT DE process_bloodhound_data ---
def process_bloodhound_data(pulled_items: list, domain_name: str, domain_root_dn_input: str):
    logging.info(f"BH Gen: Processing {len(pulled_items)} items for BloodHound (domain: {domain_name})")
    users_bh, computers_bh, groups_bh, domains_bh, ous_bh, gpos_bh = [], [], [], [], [], []
    domain_sid_str, domain_guid_str = "", ""

    for item in pulled_items: # Recherche de l'objet domaine d'abord
        dn = item.get("distinguishedName", "").lower()
        object_classes = [str(oc).lower() for oc in item.get("objectClass", [])]
        if ("domain" in object_classes or "domaindns" in object_classes) and dn == domain_root_dn_input.lower():
            raw_sid = item.get("objectSid") # Devrait être une chaîne B64
            raw_guid = item.get("objectGUID") # Devrait être une chaîne B64
            if raw_sid and isinstance(raw_sid, str):
                try: domain_sid_str = LDAP_SID(data=b64decode(raw_sid)).formatCanonical()
                except Exception as e: logging.warning(f"BH: Error decoding domain SID '{raw_sid[:30]}...': {e}")
            if raw_guid and isinstance(raw_guid, str):
                try: domain_guid_str = str(UUID(bytes_le=b64decode(raw_guid)))
                except Exception as e: logging.warning(f"BH: Error decoding domain GUID '{raw_guid[:30]}...': {e}")
            
            domains_bh.append({
                "Name": domain_name.upper(), "Guid": domain_guid_str or str(UUID()), "Sid": domain_sid_str,
                "Properties": {
                    "name": domain_name.upper(), "domainsid": domain_sid_str, 
                    "distinguishedname": item.get("distinguishedName", domain_root_dn_input), "highvalue": True,
                    "description": item.get("description"), "whencreated": item.get("whenCreated"),
                    "domainfunctionallevel": item.get("msDS-Behavior-Version")
                },
                "IsDeleted": False, "GpoRights": [], "Trusts": [], "Aces": [],
            })
            logging.info(f"BH: Domain object processed: {domain_name.upper()} (SID: {domain_sid_str})")
            break 
    
    if not domains_bh:
        logging.warning(f"BH: Domain object for '{domain_name}' not found based on DN '{domain_root_dn_input}'. Creating minimal node.")
        domain_guid_str = str(UUID()) # Nouveau GUID si non trouvé
        domains_bh.append({
            "Name": domain_name.upper(), "Guid": domain_guid_str, "Sid": domain_sid_str, # domain_sid_str sera vide
            "Properties": {"name": domain_name.upper(), "domainsid": domain_sid_str, "highvalue": True},
            "IsDeleted": False, "GpoRights": [], "Trusts": [], "Aces": []
        })

    for item_raw in pulled_items:
        item = {} # Dictionnaire pour les valeurs potentiellement décodées/formatées
        for k_raw, v_raw in item_raw.items():
            if k_raw in ["objectSid", "objectGUID", "nTSecurityDescriptor", "msDS-AllowedToActOnBehalfOfOtherIdentity"] and isinstance(v_raw, str):
                try:
                    item[k_raw] = b64decode(v_raw) # Décode en bytes pour traitement interne
                except Exception:
                    item[k_raw] = v_raw # Garde la chaîne si le décodage échoue
                    logging.debug(f"BH: Failed to b64decode attribute {k_raw} for {item_raw.get('distinguishedName')}")
            else:
                item[k_raw] = v_raw

        dn = item.get("distinguishedName", "")
        obj_sid_bytes = item.get("objectSid")
        obj_guid_bytes = item.get("objectGUID")
        object_classes = [str(oc).lower() for oc in item.get("objectClass", [])]
        
        obj_sid_str, obj_guid_str = "", ""
        if isinstance(obj_sid_bytes, bytes):
            try: obj_sid_str = LDAP_SID(data=obj_sid_bytes).formatCanonical()
            except: pass # Erreur déjà loggée si applicable
        elif isinstance(obj_sid_bytes, str) : # Au cas où c'est déjà une chaîne (improbable si bien collecté)
             obj_sid_str = obj_sid_bytes

        if isinstance(obj_guid_bytes, bytes):
            try: obj_guid_str = str(UUID(bytes_le=obj_guid_bytes))
            except: pass
        elif isinstance(obj_guid_bytes, str):
            obj_guid_str = obj_guid_bytes
            
        if not obj_sid_str and not obj_guid_str: logging.debug(f"BH: Skipping {dn}, no SID/GUID after decode."); continue
        
        obj_type = None
        if "computer" in object_classes: obj_type = "Computer"
        elif "user" in object_classes: obj_type = "User"
        elif "group" in object_classes: obj_type = "Group"
        elif "organizationalunit" in object_classes: obj_type = "OU"
        elif "grouppolicycontainer" in object_classes: obj_type = "GPO"
        elif "domain" in object_classes or "domaindns" in object_classes: continue
        else: logging.debug(f"BH: Unknown type for {dn} ({object_classes})."); continue

        bh_node = {
            "ObjectIdentifier": obj_sid_str or obj_guid_str, # Préfère SID
            "ObjectType": obj_type,
            "Properties": {"domain": domain_name.upper(), "domainsid": domain_sid_str},
            "Aces": [], "IsDeleted": False, "Links": [], "SPNTargets": [],
            "AllowedToDelegate": [], "AllowedToAct": [], "HasSIDHistory": [],
            # Pour les groupes
            "Members": [], 
            # Pour les utilisateurs/ordinateurs
            "PrimaryGroupSID": None, "MemberOf": [], 
        }
        
        for prop_name_raw, prop_value_raw in item_raw.items():
            prop_name = prop_name_raw.lower()
            # Copier la plupart des propriétés telles quelles (après un premier décodage si nécessaire)
            # Les propriétés spécifiques (UAC, SD etc.) seront traitées plus bas
            if prop_name not in bh_node["Properties"]: # Évite d'écraser "domain" et "domainsid"
                if isinstance(item.get(prop_name_raw), bytes): # Si c'est encore des bytes (ex: nTSecurityDescriptor)
                    if prop_name_raw == "nTSecurityDescriptor":
                        bh_node["Properties"][prop_name] = b64encode(item[prop_name_raw]).decode() # Stocker en B64
                    # else: # Autres bytes non gérés spécifiquement
                        # bh_node["Properties"][prop_name] = f"<binary {prop_name}>"
                else:
                    bh_node["Properties"][prop_name] = item.get(prop_name_raw)

        # Nommage
        sAMAccountName = item.get("sAMAccountName", item.get("cn", ""))
        if isinstance(sAMAccountName, list): sAMAccountName = sAMAccountName[0] if sAMAccountName else ""

        if obj_type == "User": bh_node["Name"] = f"{str(sAMAccountName).upper()}@{domain_name.upper()}"
        elif obj_type == "Computer": bh_node["Name"] = f"{str(item.get('dNSHostName', str(sAMAccountName) + '$')).upper()}"
        elif obj_type == "Group": bh_node["Name"] = f"{str(sAMAccountName).upper()}@{domain_name.upper()}"
        elif obj_type == "OU": bh_node["Name"] = str(item.get("name", dn.split(',')[0].split('=')[1])).upper() # Prend le premier RDN comme nom
        elif obj_type == "GPO": bh_node["Name"] = str(item.get("displayName", item.get("cn", dn.split(',')[0].split('=')[1]))).upper()

        # UAC
        uac_val = item.get("userAccountControl")
        if uac_val is not None:
            try:
                uac = int(uac_val)
                bh_node["Properties"]["enabled"] = not bool(uac & 0x0002)      # ADS_UF_ACCOUNTDISABLE
                bh_node["Properties"]["trustedtoauthfordelegation"] = bool(uac & 0x01000000) # ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
                bh_node["Properties"]["passwordnotreqd"] = bool(uac & 0x0020)   # ADS_UF_PASSWD_NOTREQD
                bh_node["Properties"]["dontreqpreauth"] = bool(uac & 0x00400000) # ADS_UF_DONT_REQUIRE_PREAUTH
                bh_node["Properties"]["unconstraineddelegation"] = bool(uac & 0x00080000) # ADS_UF_TRUSTED_FOR_DELEGATION
                if obj_type == "User":
                     bh_node["Properties"]["sensitive"] = bool(uac & 0x00100000) # ADS_UF_NOT_DELEGATED
            except ValueError: pass
        
        # TODO: Parsing de nTSecurityDescriptor pour ACEs
        # sd_b64 = bh_node["Properties"].get("ntsecuritydescriptor")
        # if sd_b64: bh_node["Aces"] = parse_sd_for_bh(b64decode(sd_b64))

        # TODO: Traiter member, memberOf, msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity pour les relations
        # Par exemple, pour msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD):
        # sd_rbcd_b64 = bh_node["Properties"].get("msds-allowedtoactonbehalfofotheridentity")
        # if sd_rbcd_b64:
        #     parsed_rbcd_sids = parse_sd_for_trustees(b64decode(sd_rbcd_b64)) # Fonction à créer
        #     for sid_trustee in parsed_rbcd_sids:
        #         bh_node["AllowedToAct"].append({"ObjectIdentifier": sid_trustee, "ObjectType": "User"}) # Ou Computer

        if obj_type == "User": users_bh.append(bh_node)
        elif obj_type == "Computer": computers_bh.append(bh_node)
        elif obj_type == "Group": groups_bh.append(bh_node)
        elif obj_type == "OU": ous_bh.append(bh_node)
        elif obj_type == "GPO": gpos_bh.append(bh_node)

    output_base = f"bh_adws_{domain_name.lower()}"
    def write_bh_json(data, suffix, type_str):
        if not data: return
        path = f"{output_base}_{suffix}.json"
        meta = {"count": len(data), "type": type_str, "version": 5, "methods":0, "params":{}}
        try:
            with open(path, 'w', encoding='utf-8') as f: json.dump({"data": data, "meta": meta}, f, ensure_ascii=False, indent=2)
            logging.info(f"BloodHound JSON V5 written to {path} ({len(data)} {type_str})")
        except Exception as e: logging.error(f"Error writing BH file {path}: {e}")

    write_bh_json(domains_bh, "domains", "domains")
    write_bh_json(users_bh, "users", "users")
    write_bh_json(computers_bh, "computers", "computers")
    write_bh_json(groups_bh, "groups", "groups")
    write_bh_json(ous_bh, "ous", "ous")
    write_bh_json(gpos_bh, "gpos", "gpos")

    logging.info("BloodHound data processing complete.")