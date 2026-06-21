SEND                                                            RECEIVE

[FILE / DATA (z.B. 100 MB)]                             +---------------------------+
            │                                           | Application Layer         |
            ▼                                           | - Datei / Message fertig  |
+---------------------------+                           +---------------------------+
| Fragmentation Layer       |                                     ▲
| - split in chunks         |                           +---------------------------+
| - seq / frag_index        |                           | Reassembly Layer          |
+---------------------------+                           | - Fragmente zusammenfügen |
            │                                           | - Reihenfolge sortieren   |
            ▼                                           +---------------------------+
+---------------------------+                                     ▲
| Packet Builder            |                           +---------------------------+
| - Header bauen            |                           | Packet Parser             |
| - ConnID setzen           |                           | - Header lesen            |
| - Payload anhängen        |                           | - ConnID / Seq / Flags    |
+---------------------------+                           | - Payload extrahieren     |
            │                                           +---------------------------+
            ▼                                                     ▲
+---------------------------+                           +---------------------------+
| Mesh / Translation Layer  |                           | Mesh / Translation Layer  |
| - mapping zu IPv6        |                           | - IPv6 → Mesh Paket       |
| - ggf. weitere headers    |                           | - Header entfernen        |
+---------------------------+                           +---------------------------+
            │                                                     ▲
            ▼                                                     ▲
+---------------------------+                           +---------------------------+
| IPv6 Stack                |                           | IPv6 Stack                |
| - MTU handling           |                           | - Routing / MTU Handling  |
| - routing                |                           +---------------------------+
+---------------------------+                                     ▲
            │                                                     ▲
            ▼                                                     ▲
        INTERNET                                      Physical / Link Layer
                                                     - WLAN / Ethernet





# SIP

## Was ist das?

MeshNet ist ein experimentelles, dezentrales Overlay-Netzwerk-Protokoll. Ziel ist es, eine sichere, zensurresistente Kommunikationsschicht zu bauen, die **komplett unabhängig von klassischen DNS- und IP-Adress-Systemen** funktioniert.

Statt IPv6-Adressen oder Domains als Identität zu nutzen, basiert MeshNet auf **kryptografischen Identitäten** — jedes Gerät ist durch seinen Ed25519 Public Key eindeutig identifiziert. IPv6 ist nur noch ein Transportmittel, keine Identität mehr.

---

## Kernideen

### Adressierung
- Jedes Gerät hat eine **mesh-Adresse** — ein SHA256-Hash des eigenen Public Keys
- Diese Adresse ist permanent und gerätegebunden — egal wie oft sich die IPv6-Adresse ändert
- Menschenlesbare Namen existieren nur **lokal** als Aliases (wie ein Telefonbuch) — global kennt das Netz nur den Hash

### Kein DNS
- Keine zentralen Server, keine Registrare, kein Single Point of Failure
- Neue Geräte werden per **Bootstrap** (einmaliger Kontakt via IPv6) ins Netz aufgenommen
- Danach läuft alles über die lokale Registry — eine JSON-Datei mit bekannten Peers

### Sicherheit
- **Ed25519** für Identität und Signaturen
- **X25519** für ephemeral Key Exchange (Forward Secrecy)
- **ChaCha20-Poly1305** für Datenverschlüsselung
- **AES-256-GCM** für lokale Key-Speicherung
- Jede Session hat einen eigenen kurzlebigen Session Key

### Transport
- Eigenes binäres Paketformat mit 48-Byte Header
- Multipath-Unterstützung — Daten können über mehrere IPv6-Adressen gleichzeitig gesendet werden
- Fragmentierung für große Datenmengen
- IPv6 ist nur der Träger — das Mesh-Protokoll läuft darüber

---

## Projektstruktur

### Python (Prototyp)
| Datei | Funktion |
|---|---|
| `netIP.py` | Key-Management (Ed25519, AES-GCM) |
| `registry.py` | Lokale Peer-Datenbank |
| `bootstrap.py` | Erstkontakt mit neuem Peer |
| `session.py` | X25519 Key Exchange + Session-Verwaltung |
| `header.py` | Paket-Header bauen/parsen |
| `fragmentation.py` | Große Daten aufteilen |
| `translation.py` | Verschlüsseln + Multipath-Routing |
| `server.py` | TCP/UDP Server + Routing |
| `resolve.py` | Domain-Auflösung mit Fallbacks |

### Zig (Produktion, in Entwicklung)
| Datei | Funktion |
|---|---|
| `address.zig` | Key-Management + Adressableitung |
| `header.zig` | Paket-Header bauen/parsen |

---

## Typischer Ablauf
Erstkontakt
python bootstrap.py --bootstrap <ipv6-des-peers>
→ tauscht Public Keys + mesh-Adressen aus
→ speichert Peer in lokaler Registry
Session aufbauen
python main_session.py
→ X25519 Key Exchange
→ Ed25519 Signatur-Verifikation
→ Session Key wird abgeleitet
Kommunikation
Daten → Header → Fragmentierung → Verschlüsselung → IPv6/UDP → Peer
Peer  → Entschlüsselung → Reassemblierung → Header parsen → Anwendung


---

## Was noch fehlt

- [ ] Zig: TCP Server
- [ ] Zig: Session-Management
- [ ] Zig: Translation Layer (ChaCha20)
- [ ] Gossip-Protokoll für Adress-Updates
- [ ] Negotiation (wieviele Multipath-Pfade)
- [ ] ACK-System für zuverlässige Übertragung
- [ ] Android/iOS Client

---

## Abhängigkeiten

### Python
pip install cryptography

### Zig
- Zig 0.16.0
- Nur `std` — keine externen Abhängigkeiten

---

## Sicherheitshinweis

Dies ist ein experimenteller Prototyp. Nicht für produktiven Einsatz geeignet.





