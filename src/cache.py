import json
from collections import defaultdict
from typing import Dict, Tuple, List, Optional

class Label:
    Base = "Base"  # Placeholder, replace with actual enum or class

class TypedPrincipal:
    def __init__(self, object_identifier: str = "", object_type: Label = Label.Base):
        self.object_identifier = object_identifier
        self.object_type = object_type

class Cache:
    ValueToIdCache: Dict[str, str] = {}
    IdToTypeCache: Dict[str, Label] = {}

    @staticmethod
    def deserialize(path: str):
        with open(path, 'r', encoding='utf-8') as file:
            temp_cache = json.load(file)
            Cache.ValueToIdCache = {k.lower(): v for k, v in temp_cache["ValueToIdCache"].items()}
            Cache.IdToTypeCache = {k: v for k, v in temp_cache["IdToTypeCache"].items()}

    @staticmethod
    def serialize(path: str):
        temp_cache = {
            "ValueToIdCache": Cache.ValueToIdCache,
            "IdToTypeCache": Cache.IdToTypeCache,
        }
        with open(path, 'w', encoding='utf-8') as file:
            json.dump(temp_cache, file, indent=4)

    @staticmethod
    def add_converted_value(key: str, value: str):
        key_lower = key.lower()
        if key_lower in Cache.ValueToIdCache:
            print(f"Duplicate key found with value: {key}")
        else:
            Cache.ValueToIdCache[key_lower] = value

    @staticmethod
    def add_type(key: str, value: Label):
        if key in Cache.IdToTypeCache:
            print(f"Duplicate key found with value: {key}")
        else:
            Cache.IdToTypeCache[key] = value

    @staticmethod
    def get_converted_value(key: str) -> Tuple[bool, Optional[str]]:
        return key.lower() in Cache.ValueToIdCache, Cache.ValueToIdCache.get(key.lower())

    @staticmethod
    def get_id_type(key: str) -> Tuple[bool, Label]:
        return key in Cache.IdToTypeCache, Cache.IdToTypeCache.get(key, Label.Base)

    @staticmethod
    def get_child_objects(dn: str) -> Tuple[bool, List[TypedPrincipal]]:
        child_objects = []
        matching_keys = [k for k in Cache.ValueToIdCache if dn in k and k != dn]

        for key in matching_keys:
            if Cache.is_distinguished_name_filtered(key):
                continue
            found, id_value = Cache.get_converted_value(key)
            if found:
                type_found, obj_type = Cache.get_id_type(id_value)
                child_objects.append(TypedPrincipal(object_identifier=id_value.upper(), object_type=obj_type))
        
        return bool(matching_keys), child_objects

    @staticmethod
    def get_domain_child_objects(dn: str) -> Tuple[bool, List[TypedPrincipal]]:
        dn_level = dn.count('=')
        child_objects = []
        matching_keys = [k for k in Cache.ValueToIdCache if dn in k and k != dn]

        for key in matching_keys:
            if key.count('=') != (dn_level + 1):
                continue
            if Cache.is_distinguished_name_filtered(key):
                continue
            found, id_value = Cache.get_converted_value(key)
            if found:
                type_found, obj_type = Cache.get_id_type(id_value)
                child_objects.append(TypedPrincipal(object_identifier=id_value.upper(), object_type=obj_type))
        
        return bool(matching_keys), child_objects

    @staticmethod
    def is_distinguished_name_filtered(distinguished_name: str) -> bool:
        dn = distinguished_name.upper()
        return "CN=PROGRAM DATA,DC=" in dn or "CN=SYSTEM,DC=" in dn

    @staticmethod
    def get_cache_stats() -> str:
        try:
            return (f"{len(Cache.IdToTypeCache)} ID to type mappings.\n"
                    f"{len(Cache.ValueToIdCache)} name to SID mappings.\n")
        except:
            return ""
