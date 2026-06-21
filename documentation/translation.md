
## 1. Die zwei Richtungen im Überblick

```
                         translation.zig
                    ┌────────────────────────┐
  fertige Daten     │                        │   verschlüsselte
  (SIP-Paket) ──────►   translateOutbound()  ├────► Fragmente
                    │                        │   (Liste von []u8)
                    └────────────────────────┘

                    ┌────────────────────────┐
  ein empfangenes   │                        │   null  (warte noch)
  verschlüsseltes   │   translateInbound()   ├────►  oder
  Fragment ─────────►                        │   zusammengesetzte
                    └────────────────────────┘   Originaldaten
```

`translateOutbound` wird **einmal pro zu sendender Nachricht** aufgerufen
und gibt **mehrere** Pakete zurück (eines pro Fragment).

`translateInbound` wird **einmal pro empfangenem Paket** aufgerufen und
gibt **entweder nichts Brauchbares (`null`) oder genau eine fertige
Nachricht** zurück.

---

## 2. OUTBOUND — von Rohdaten zu versandfertigen Paketen

### 2.1 Schritt 1: Fragmentieren

```zig
const fragments = try frag.fragmentData(allocator, data, src, dst, conn_id);
```


```
  Original-Daten (z.B. 3000 Byte)
  ┌──────────────────────────────────────────────────┐
  │//////////////////////////////////////////////////│
  └──────────────────────────────────────────────────┘
                         │
                         │  frag.fragmentData()
                         │  (aus fragmentation.zig, NICHT translation.zig)
                         ▼
  ┌──────────────┐  ┌──────────────┐  ┌──────────┐
  │ Fragment 0   │  │ Fragment 1   │  │Fragment 2│
  │ Hdr|Payload  │  │ Hdr|Payload  │  │Hdr|Payload│
  │ seq=0        │  │ seq=1        │  │seq=2     │
  │ total=3      │  │ total=3      │  │total=3   │
  │ (1200 Byte)  │  │ (1200 Byte)  │  │(600 Byte)│
  └──────────────┘  └──────────────┘  └──────────┘
```

Jedes Fragment hat schon einen eigenen Header mit:
- `seq` — Position in der Nachricht (0, 1, 2, ...)
- `total_fragments` — wie viele Fragmente die ganze Nachricht hat
- `is_last`-Flag — ob es das letzte Fragment ist

`translation.zig` selbst entscheidet **nicht**, wie groß die Stücke sind —
das ist komplett Aufgabe von `fragmentation.zig`. `translation.zig`
bekommt einfach eine fertige Liste.

Hierzu ist zu erwähnen, dass das komplette fragmentierung system unter SIP zurzeit nicht weiter entwickelt wird, da sich zurzeit eher auf die translation nach tcp konzentriert wird und dafür eine eigenen fragemntation nciht nötig ist. falls in der zukunft kompatiblität in udp oder raw IP nötig ist, wird villeicht fragemntaiton.zig fertiggestellt.

### 2.2 Schritt 2: Jedes Fragment einzeln verschlüsseln

Für jedes Fragment aus der Liste wird `encryptFragment()` aufgerufen:

```zig
for (fragments.items, 0..) |f, i| {
    out[i] = try encryptFragment(io, allocator, f.data, key);
}
```

Schauen wir uns **ein** Fragment im Detail an:

```
  Rohes Fragment (von fragmentation.zig):
  ┌─────────────────┬──────────────────────────┐
  │  Header (42 B)  │     Payload (≤1200 B)    │
  └─────────────────┴──────────────────────────┘
         │                       │
         │                       │
    bleibt LESBAR           wird VERSCHLÜSSELT
    (für Routing)           (Inhalt geheim)
         │                       │
         ▼                       ▼
  ┌─────────────────┐   ┌──────────────────────┐
  │  Header (50 B)  │   │ ChaCha20-Poly1305     │
  │  als "AAD"      │──►│ encrypt()             │
  │  mitgegeben     │   │                       │
  └─────────────────┘   └───────────┬───────────┘
                                     │
                       ┌─────────────┴─────────────┐
                       │                            │
                       ▼                            ▼
              Ciphertext (≤1200 B)          Auth-Tag (16 B)
              (verschlüsselter Payload)     ("Siegel")
```

**Was ist AAD (Additional Authenticated Data)?**

```
  Normalerweise verschlüsselt man "alles". Hier wird der Header
  bewusst NICHT verschlüsselt, aber trotzdem "mit besiegelt":

  ┌─────────────────────────────────────────────────────────┐
  │  encrypt(payload, header_als_AAD, nonce, key)            │
  │                                                            │
  │  → der Payload wird unlesbar (Ciphertext)                 │
  │  → der Header bleibt lesbar, ABER:                        │
  │    wird auch nur 1 Byte im Header verändert, schlägt      │
  │    die spätere Prüfung (decrypt) fehl, obwohl der Header   │
  │    selbst nie "entschlüsselt" werden musste.               │
  └─────────────────────────────────────────────────────────┘

  Grund: ein Router/Server soll den Header lesen können (um zu
  wissen wohin das Paket soll), OHNE den geheimen Schlüssel zu
  kennen. Aber niemand darf den Header unbemerkt verändern können.
```

### 2.3 Schritt 3: Alles zusammenpacken

```
  Fertiges, versandfertiges Fragment:

  ┌──────────┬───────────┬─────────────────────┬──────────┐
  │ Header   │  Nonce    │     Ciphertext      │ Auth-Tag │
  │ (42 B)   │  (12 B)   │   (= Payload-Länge) │  (16 B)  │
  └──────────┴───────────┴─────────────────────┴──────────┘
   lesbar      lesbar         unlesbar             lesbar
   (als AAD    (muss beim                        (Prüfsumme,
   geprüft)    Empfänger                          beweist Echtheit)
               wieder rein)
```

Diese Bytes werden zurückgegeben. **Was danach damit passiert (über UDP
verschicken, über ein Raw-IPv6-Paket, etc.) macht `translation.zig`
nicht mehr selbst** — das übernimmt der aufrufende Code.

### 2.4 Gesamtbild Outbound

```
   data (z.B. 3000 Byte)
        │
        ▼
  ┌─────────────────────┐
  │ frag.fragmentData() │   ── erzeugt 3 rohe Fragmente
  └──────────┬──────────┘      (mit Header+Payload, unverschlüsselt)
             │
             ▼
   ┌─────────────────────────────────────────┐
   │  for jedes Fragment:                     │
   │     encryptFragment()                    │
   │       1. Nonce ziehen                    │
   │       2. ChaCha20-Poly1305 verschlüsseln │
   │       3. [Header|Nonce|Ciphertext|Tag]   │
   └──────────┬────────────────────────────────┘
              │
              ▼
   Liste von 3 fertigen, verschlüsselten Paketen
   → wird zurückgegeben
```

---

## 3. INBOUND — von empfangenen Bytes zur Originalnachricht

Wichtig: diese Funktion läuft **pro empfangenem Paket**, nicht pro
Nachricht. Der Server ruft sie für jedes ankommende Stück erneut auf.

```zig
pub fn translateInbound(allocator, data, key, buf: *ReassemblyBuffer) !?[]u8
```

### 3.1 Schritt 1: Entschlüsseln + Echtheit prüfen

```
  Empfangenes Paket:
  ┌──────────┬───────────┬─────────────────────┬──────────┐
  │ Header   │  Nonce    │     Ciphertext      │ Auth-Tag │
  └──────────┴───────────┴─────────────────────┴──────────┘
        │
        │  decryptFragment()
        ▼
  ┌─────────────────────────────────────────────────┐
  │  1. Ist das Paket überhaupt lang genug?          │
  │     (Header + Nonce + Tag als Minimum)           │
  │     NEIN → error.PacketTooSmall, sofort verworfen│
  │                                                    │
  │  2. ChaCha20Poly1305.decrypt(...)                │
  │     prüft: passt der Auth-Tag zu                  │
  │     (Header als AAD + Ciphertext + Nonce + Key)?  │
  │                                                    │
  │     NEIN → error.AuthFailed                       │
  │            (KEINE genauere Fehlermeldung,          │
  │             damit ein Angreifer durch Ausprobieren│
  │             nichts über den Grund lernt)           │
  │                                                    │
  │     JA   → Payload ist jetzt entschlüsselt,        │
  │            Header+Payload geben wir weiter         │
  └─────────────────────────────────────────────────┘
```

Wenn hier irgendetwas manipuliert wurde — egal ob Header, Ciphertext,
Nonce oder Tag — kommt **nur** `error.AuthFailed` zurück. Das Fragment
wird komplett verworfen und kommt nie in den Reassembly-Speicher.

### 3.2 Schritt 2: Header lesen

```zig
const parsed = try header.parsePacket(decrypted);
```

```
  Erst NACH erfolgreicher Entschlüsselung wird der Header offiziell
  interpretiert (Magic-Byte prüfen, Felder auslesen):

  entschlüsselte Bytes
  ┌──────────────────────────┬─────────────────────┐
  │  Header (42 Byte)        │  Payload            │
  │  - magic                 │  (Originaldaten     │
  │  - src/dst               │   dieses Fragments) │
  │  - conn_id               │                     │
  └──────────────────────────┴─────────────────────┘

  Reihenfolge ist bewusst: ERST entschlüsseln/prüfen, DANN
  interpretieren. Nie andersrum — sonst könnte ein nicht-vertrauens-
  würdiger Header schon vor der Echtheitsprüfung Schaden anrichten.
```

### 3.3 Schritt 3: Herausfinden, zu welcher Nachricht das Fragment gehört

```zig
const decoded = frag.decodeConnId(parsed.header.conn_id);
```

```
  conn_id ist eine einzige 64-Bit-Zahl, die mehrere Infos codiert:

  ┌────────────────────────────┬──────────────────┬────────┐
  │  base_id (32 Bit)           │  seq (24 Bit)     │ flags  │
  │  "zu welcher Nachricht      │  "welche Position │ (8 Bit)│
  │   gehört das?"               │   innerhalb der    │        │
  │                              │   Nachricht?"      │        │
  └────────────────────────────┴──────────────────┴────────┘

  Zusätzlich, aus dem Header (NICHT aus conn_id):
  total_fragments → "wie viele Fragmente hat die GANZE Nachricht?"
```

> **Verbesserung, die wir gemeinsam eingebaut haben:** früher musste
> `total` aus dem *letzten* Fragment erraten werden (`seq + 1`, wenn
> `is_last` gesetzt war). Jetzt steht `total_fragments` direkt in
> **jedem einzelnen** Fragment-Header — der Empfänger weiß es also
> sofort beim ersten ankommenden Stück, egal in welcher Reihenfolge die
> Fragmente eintreffen.

### 3.4 Schritt 4: Ins Reassembly-Gedächtnis einsortieren

```zig
const result = try buf.insert(decoded.base_id, decoded.seq,
                                parsed.header.total_fragments, parsed.payload);
```

Das ist das Herzstück — wie ein Postfach, das einzelne Briefumschläge
sammelt, bis alle für einen bestimmten Absender da sind:

```
  ReassemblyBuffer (buf)
  ┌─────────────────────────────────────────────────────┐
  │  map: base_id → FragmentStore                        │
  │                                                        │
  │  base_id=42:  FragmentStore { total=3,                │
  │                                 fragments: {           │
  │                                   0: "foo",            │
  │                                   2: "baz"             │
  │                                   // seq=1 fehlt noch  │
  │                                 }}                     │
  │                                                        │
  │  base_id=99:  FragmentStore { total=1,                │
  │                                 fragments: { 0: "x" }} │
  └─────────────────────────────────────────────────────┘
```

Die Prüfungen, in der Reihenfolge, in der sie passieren:

```
  insert(base_id, seq, total, payload)
        │
        ▼
  ┌─────────────────────────────────────────┐
  │ 1. total == 0 ?                          │  → error.InvalidSeq
  │    total > MAX_FRAGMENTS_PER_MESSAGE ?   │  → error.TooManyFragments
  │    seq >= total ?                        │  → error.InvalidSeq
  │                                           │
  │    Diese 3 Checks laufen BEVOR irgendwas │
  │    alloziert wird — wichtig für Schutz   │
  │    vor Speicher-Erschöpfung (DoS).       │
  └──────────────────┬────────────────────────┘
                     │ alles ok
                     ▼
  ┌─────────────────────────────────────────┐
  │ 2. Gibt es schon einen Store für         │
  │    diesen base_id?                       │
  │    NEIN → neu anlegen, total merken      │
  │    JA   → stimmt total mit dem           │
  │           gemerkten total überein?       │
  │           NEIN → error.InconsistentTotal │
  └──────────────────┬────────────────────────┘
                     │ ok
                     ▼
  ┌─────────────────────────────────────────┐
  │ 3. Fragment unter seq abspeichern        │
  │    (war schon eins unter dieser seq da?  │
  │     → altes freigeben, neues nehmen,     │
  │     z.B. bei einem Retransmit)           │
  └──────────────────┬────────────────────────┘
                     │
                     ▼
  ┌─────────────────────────────────────────┐
  │ 4. Sind jetzt schon `total` Fragmente    │
  │    für diesen base_id gespeichert?       │
  │    NEIN → return null  ("warte weiter")  │
  │    JA   → alle Stücke 0..total-1 in      │
  │           Reihenfolge zusammenkopieren,  │
  │           Store aus dem Speicher löschen,│
  │           Ergebnis zurückgeben           │
  └─────────────────────────────────────────┘
```

### 3.5 Beispiel: drei Fragmente kommen in falscher Reihenfolge an

```
  Ankunft:  Fragment(seq=2, total=3) kommt ZUERST an
            │
            ▼
  insert(base_id=7, seq=2, total=3, "baz")
  → Store für base_id=7 neu angelegt, total=3 gemerkt
  → fragments: { 2: "baz" }
  → 1 von 3 da → return null


  Ankunft:  Fragment(seq=0, total=3)
            │
            ▼
  insert(base_id=7, seq=0, total=3, "foo")
  → fragments: { 0: "foo", 2: "baz" }
  → 2 von 3 da → return null


  Ankunft:  Fragment(seq=1, total=3)
            │
            ▼
  insert(base_id=7, seq=1, total=3, "bar")
  → fragments: { 0: "foo", 1: "bar", 2: "baz" }
  → 3 von 3 da!  → zusammenkopieren: "foo" + "bar" + "baz"
  → return "foobarbaz"
```

Das funktioniert unabhängig davon, in welcher Reihenfolge die Fragmente
eintreffen — genau das war der Sinn der `total_fragments`-Änderung.

### 3.6 Gesamtbild Inbound

```
   ein empfangenes Paket (rohe Bytes von der Leitung)
        │
        ▼
  ┌─────────────────────┐
  │  decryptFragment()   │ ── zu kurz? → PacketTooSmall
  └──────────┬───────────┘ ── Tag falsch? → AuthFailed
             │ ok
             ▼
  ┌─────────────────────┐
  │  header.parsePacket()│ ── Magic-Byte prüfen, Felder lesen
  └──────────┬───────────┘
             │
             ▼
  ┌─────────────────────┐
  │  frag.decodeConnId() │ ── base_id, seq extrahieren
  └──────────┬───────────┘
             │
             ▼
  ┌─────────────────────┐
  │  buf.insert(...)      │ ── Cap-Check, Konsistenz-Check,
  └──────────┬───────────┘    speichern, ggf. zusammensetzen
             │
             ▼
     null  (noch nicht komplett)
        oder
     []u8  (fertige Originaldaten)
```

---

## 4. Was sich durch den Umbau geändert hat (kurze Erinnerung)

| Vorher | Jetzt |
|---|---|
| `total` wurde aus `seq + 1` beim letzten Fragment **abgeleitet** | `total_fragments` steht **explizit** in jedem Fragment-Header |
| Geht das letzte Fragment verloren/kommt spät an → `total` unbekannt | `total` ist ab dem ersten Fragment bekannt |
| Kein Cap — beliebig viele Fragmente konnten gesammelt werden | Harter Cap `MAX_FRAGMENTS_PER_MESSAGE` (Standard: 4096), geprüft **vor** jeder Allokation |
| Kein Schutz vor widersprüchlichen `total`-Werten | `InconsistentTotal`-Fehler, wenn ein späteres Fragment ein anderes `total` behauptet |
| Duplikat-Fragmente (Retransmits) wurden nicht behandelt | Altes Fragment wird korrekt freigegeben, neues ersetzt es |

---

## 5. Was man noch ändern/ergänzen könnte

Das hier sind Beobachtungen, keine fertigen Patches — manche sind reine
Designentscheidungen, die du bewusst treffen solltest, statt dass ich sie
einfach umsetze.

### 5.1 Nonce-Volumen im Blick behalten

Aktuell wird **pro Fragment** eine neue 12-Byte-Zufalls-Nonce gezogen
(nicht eine pro Nachricht). Bei zufälligen Nonces gilt laut Kryptografie-Literatur
zu ChaCha20-Poly1305: man kann mit demselben Schlüssel etwa 2^48 Nachrichten verschlüsseln, bei vernachlässigbarer Kollisionswahrscheinlichkeit (2^-32, in Übereinstimmung mit NIST-Richtlinien).

Das ist eine extrem hohe Grenze (281 Billionen Fragmente) und für die
meisten Einsatzszenarien kein praktisches Problem. Trotzdem lohnt es
sich, das im Hinterkopf zu behalten, falls:
- ein einzelner Schlüssel sehr langlebig ist (Monate/Jahre ohne Rotation)
- sehr viele kleine Fragmente Standard werden (z.B. winzige Chunk-Größe)

Mögliche Optionen, falls das relevant wird: Schlüssel-Rotation nach einer
gewissen Fragmentanzahl, oder ein Wechsel zu einem Nonce-Schema mit
größerem Sicherheitsabstand (z.B. XChaCha20-Poly1305 mit 192-Bit-Nonce
statt 96-Bit) — XChaCha20-Poly1305 erlaubt bei zufällig gewählten Nonces eine bessere Sicherheit als die ursprüngliche Konstruktion. Das wäre aber ein größerer Umbau (andere Nonce-Größe im
Wire-Format), kein kleiner Patch.

### 5.2 `get_unix_time` über C — könnte native Zig-Lösung werden

`header.zig` deklariert `get_unix_time` als `extern fn` und braucht dafür
`time.c` gelinkt. Zig 0.16 hat dafür eine native Alternative
(`std.Io.Timestamp`), die ganz ohne C-Linking funktionieren würde. Das
würde den Build vereinfachen (kein `-lc src/time.c` mehr nötig), ist
aber eine Änderung an `header.zig`, die ich nicht einfach im Hintergrund
machen wollte, ohne dass du das explizit willst.

### 5.3 Cleanup für unvollständige Reassemblies bleibt offen

Laut dem ursprünglichen Design-Rundown ist das bewusst **nicht** Aufgabe
von `translation.zig` — ein Server-seitiger periodischer Cleanup-Thread
soll alte, nie vollständig gewordene Einträge im `ReassemblyBuffer`
irgendwann entfernen. Der harte Cap (`MAX_FRAGMENTS_PER_MESSAGE`)
begrenzt nur, *wie groß* eine einzelne unvollständige Sammlung werden
kann — nicht, *wie lange* sie im Speicher bleibt, wenn das letzte
Fragment nie ankommt. Ohne diesen Cleanup-Mechanismus können sich über
Zeit beliebig viele solcher (begrenzt großen) unvollständigen Sammlungen
ansammeln. Das ist nicht vergessen, sondern eine bewusste
Abgrenzung — aber falls noch kein Cleanup-Code existiert, ist das ein
offener Punkt, der vor dem produktiven Einsatz noch gebaut werden muss.

### 5.4 Sichtbarkeit von Fragmentanzahl/Reihenfolge auf der Leitung

`seq`, `total_fragments` und das `is_last`-Flag liegen im unverschlüsselten
Header (nur als AAD geprüft, nicht versteckt). Das bedeutet: jeder, der
den Netzwerkverkehr mitschneidet, sieht, wie viele Fragmente eine
Nachricht hat und in welcher Reihenfolge sie ankommen — auch ohne den
Schlüssel zu kennen. Das folgt direkt aus der bewussten Design-Entscheidung
"Header muss ohne Entschlüsselung routbar bleiben". Falls Traffic-Analyse
(z.B. Rückschlüsse auf Nachrichtengröße aus der Fragmentanzahl) ein
Bedrohungsmodell ist, das dich betrifft, wäre Padding auf eine feste
Fragmentanzahl eine mögliche Gegenmaßnahme — das ist aber ein
grundsätzlicher Trade-off (mehr Overhead) und keine kleine Änderung.

### 5.5 `MAX_FRAGMENTS_PER_MESSAGE` ist aktuell ein fester Wert

Der Cap (4096) ist eine `pub const` in `translation.zig` — er lässt sich
also einfach anpassen, aber er ist nicht zur Laufzeit konfigurierbar
(z.B. unterschiedliche Caps für unterschiedliche Verbindungstypen). Falls
du z.B. für manche Peers größere Nachrichten erlauben willst und für
andere strikter sein willst, müsste das ein Parameter werden, der von
außen (z.B. aus einer Server-Konfiguration) hereingereicht wird, statt
eine globale Konstante zu sein.

### 5.6 Speicherverbrauch pro angefangener Nachricht

Ein böswilliger Peer kann aktuell beliebig viele **verschiedene**
`base_id`-Werte gleichzeitig "anfangen" (je mit z.B. 1 Fragment), auch
wenn jede einzelne Sammlung durch `MAX_FRAGMENTS_PER_MESSAGE` begrenzt
ist. Es gibt aktuell keine Grenze für die **Anzahl gleichzeitig
offener `base_id`-Einträge** in der `map` selbst. Das ist verwandt mit
Punkt 5.3 (Cleanup) — ein zeitbasiertes Aufräumen würde auch das
entschärfen, aber ein zusätzlicher harter Cap auf die Anzahl
gleichzeitig offener Sammlungen (unabhängig von Cleanup) wäre eine
weitere mögliche Verteidigungsschicht.

