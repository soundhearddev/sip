import json
import os
from datetime import datetime, timedelta

JSON_FILE = "addresses.json"

def load_storage() -> list:
    """Lädt die bestehende JSON-Datei. Falls sie nicht existiert, wird eine leere Liste zurückgegeben."""
    if not os.path.exists(JSON_FILE):
        return []
    try:
        with open(JSON_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"[!] Warnung: {JSON_FILE} war beschädigt. Erstelle neu.")
        return []


def save_storage(data: list):
    """Schreibt die Daten sauber formatiert zurück in die JSON-Datei."""
    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def log_new_address(address: str, iface: str, ttl: int = None, tag: str = "default"):
    """
    Speichert eine neu generierte IPv6-Adresse mit erweiterten Metadaten in der JSON.
    """
    # Bestehende Einträge laden
    db = load_storage()
    
    # Zeitstempel vorbereiten
    now = datetime.now()
    created_at_str = now.strftime("%Y-%m-%d %H:%M:%S")
    
    # TTL und Ablaufdatum berechnen
    expires_at_str = None
    if ttl is not None:
        expire_time = now + timedelta(seconds=ttl)
        expires_at_str = expire_time.strftime("%Y-%m-%d %H:%M:%S")

    # Das Daten-Objekt für diese IP
    entry = {
        "address": address,
        "interface": iface,
        "tag": tag,
        "status": "active",
        "created_at": created_at_str,
        "ttl_seconds": ttl,
        "expires_at": expires_at_str
    }
    
    # Zur Liste hinzufügen und speichern
    db.append(entry)
    save_storage(db)
    print(f"[💾] Adresse {address} in {JSON_FILE} protokolliert.")


def clean_expired_addresses():
    """
    Optionaler Helfer: Markiert Einträge in der JSON als 'expired', 
    wenn deren Ablaufdatum in der Vergangenheit liegt.
    """
    db = load_storage()
    now = datetime.now()
    changed = False
    
    for entry in db:
        if entry["status"] == "active" and entry["expires_at"]:
            expire_time = datetime.strptime(entry["expires_at"], "%Y-%m-%d %H:%M:%S")
            if now > expire_time:
                entry["status"] = "expired"
                changed = True
                
    if changed:
        save_storage(db)
        print("[💾] JSON-Datenbank aktualisiert: Abgelaufene IPs wurden als 'expired' markiert.")