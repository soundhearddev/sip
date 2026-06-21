```
SEND                                                            RECEIVE
[FILE / DATA (z.B. 100 MB)]                              +---------------------------+
            │                                             | Application Layer        |
            ▼                                             | - Datei / Message fertig |
+---------------------------+                             +---------------------------+
| Fragmentation Layer       |                                        ▲
| - split in chunks         |                             +---------------------------+
| - seq / frag_index        |                             | Reassembly Layer         |
+---------------------------+                             | - Fragmente zusammenfügen|
            │                                             | - Reihenfolge sortieren  |
            ▼                                             +---------------------------+
+---------------------------+                                        ▲
| Packet Builder            |                             +---------------------------+
| - Header bauen            |                             | Packet Parser            |
| - ConnID setzen           |                             | - Header lesen           |
| - Payload anhängen        |                             | - ConnID / Seq / Flags   |
+---------------------------+                             | - Payload extrahieren    |
            │                                             +---------------------------+
            ▼                                                        ▲
+---------------------------+                             +---------------------------+
| Mesh / Translation Layer  |                             | Mesh / Translation Layer  |
| - mapping zu IPv6         |                             | - IPv6 → Mesh Paket      |
| - ggf. weitere headers    |                             | - Header entfernen       |
+---------------------------+                             +---------------------------+
            │                                                        ▲
            ▼                                                        │
+---------------------------+                             +---------------------------+
| IPv6 Stack                |                             | IPv6 Stack                |
| - MTU handling            |                             | - Routing / MTU Handling  |
| - routing                 |                             +---------------------------+
+---------------------------+                                        ▲
            │                                                        │
            ▼                                                        │
        INTERNET                                      Physical / Link Layer
                                                     - WLAN / Ethernet
```


# SIP

## Was ist das?

SIP ist ein experimentelles, dezentrales Overlay-Netzwerk-Protokoll. Ziel ist es, eine sichere, zensurresistente Kommunikationsschicht zu bauen, die **komplett unabhängig von klassischen TCP- und IP-Adress-Systemen** funktioniert.

Statt IPv6-Adressen oder Domains als Identität zu nutzen, basiert SIP auf **kryptografischen Identitäten** — jedes Gerät ist durch seinen Ed25519 Public Key eindeutig identifiziert. IPv6 ist nur noch ein Transportmittel, keine Identität mehr.

---

## Kernideen

### Adressierung
- Jedes Gerät hat eine **mesh-Adresse** — ein SHA256-Hash des eigenen Public Keys
- Diese Adresse ist permanent und gerätegebunden — egal wie oft sich die IPv6-Adresse ändert
- Menschenlesbare Namen existieren nur **lokal** als Aliases. Global kennt das Netz nur den Hash

### Sicherheit
- **Ed25519** für Identität und Signaturen
- **X25519** für ephemeral Key Exchange (Forward Secrecy)
- **ChaCha20-Poly1305** für Datenverschlüsselung
- **AES-256-GCM** für lokale Key-Speicherung
- Jede Session hat einen eigenen kurzlebigen Session Key

### Transport
- Eigenes binäres Paketformat mit 42-Byte Header
- Multipath-Unterstützung: Daten können über mehrere IPv6-Adressen gleichzeitig gesendet werden
- IPv6 ist nur der Träger — das Mesh-Protokoll läuft darüber




## Abhängigkeiten

### Python
``` bash
pip install cryptography
```

### Zig
- Zig 0.16.0








