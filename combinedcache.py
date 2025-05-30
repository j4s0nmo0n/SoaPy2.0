import json
import os
import logging

def combine_raw_json_files(id_to_type_path="IdToTypeCache.json", value_to_id_path="ValueToIdCache.json", output_path="CombinedCache.json"):
    """
    Loads two JSON files and combines them as nested objects in a new single JSON file.

    Args:
        id_to_type_path (str): Path to the IdToTypeCache.json file.
        value_to_id_path (str): Path to the ValueToIdCache.json file.
        output_path (str): Path where the combined JSON file will be saved.
    """
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    if not os.path.exists(id_to_type_path):
        logging.error(f"Erreur : '{id_to_type_path}' introuvable.")
        return
    if not os.path.exists(value_to_id_path):
        logging.error(f"Erreur : '{value_to_id_path}' introuvable.")
        return

    combined_data = {}

    try:
        with open(id_to_type_path, 'r', encoding='utf-8') as f:
            id_to_type_content = json.load(f)
        combined_data["IdToTypeCache"] = id_to_type_content
        logging.info(f"'{id_to_type_path}' chargé avec succès.")
    except json.JSONDecodeError as e:
        logging.error(f"Erreur de décodage JSON dans '{id_to_type_path}' : {e}")
        return
    except Exception as e:
        logging.error(f"Une erreur inattendue est survenue lors du chargement de '{id_to_type_path}' : {e}")
        return

    try:
        with open(value_to_id_path, 'r', encoding='utf-8') as f:
            value_to_id_content = json.load(f)
        combined_data["ValueToIdCache"] = value_to_id_content
        logging.info(f"'{value_to_id_path}' chargé avec succès.")
    except json.JSONDecodeError as e:
        logging.error(f"Erreur de décodage JSON dans '{value_to_id_path}' : {e}")
        return
    except Exception as e:
        logging.error(f"Une erreur inattendue est survenue lors du chargement de '{value_to_id_path}' : {e}")
        return

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(combined_data, f, indent=2, ensure_ascii=False)
        logging.info(f"Caches combinés avec succès dans '{output_path}'.")
    except IOError as e:
        logging.error(f"Erreur d'écriture du fichier combiné '{output_path}' : {e}")
    except Exception as e:
        logging.error(f"Une erreur inattendue est survenue lors de l'enregistrement du cache combiné : {e}")

if __name__ == "__main__":
    # Assurez-vous que IdToTypeCache.json et ValueToIdCache.json sont dans le même répertoire
    # ou spécifiez les chemins complets.
    combine_raw_json_files()