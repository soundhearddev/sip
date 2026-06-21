# header.zig — Ablauf im Detail

Dieses Dokument erklärt, was `header.zig` Zeile für Zeile tut, mit
ASCII-Skizzen für jeden Schritt. Am Ende steht eine Liste von Dingen, die
man noch ändern oder ergänzen könnte.

---

## 1. Die Aufgabe von header.zig in einem Satz

`header.zig` weiß, **wie ein Paket aus Bytes aufgebaut ist**, und kann
diese Bytes in beide Richtungen übersetzen:

```
   Header-Felder (Zig-Struct)  ◄─────────────►  rohe Bytes auf der Leitung
        Header{...}             buildPacket()         [0x4D, 0x01, ...]
                                 parsePacket()
```

Es weiß **nichts** über Verschlüsselung (das macht `translation.zig`) und
**nichts** über Fragmentierung (das macht `fragmentation.zig`). Es ist
reine "Byte-Buchhaltung": Felder rein, Bytes raus — und umgekehrt.

---

## 2. Das Speicherlayout (Header Layout)

So sieht ein Header als 50 zusammenhängende Bytes aus:

```
 Offset:  0    1    2 ............. 17  18 ............ 33  34 ......... 41  42... 43  44 ......... 47  48 . 49
         ┌────┬────┬──────────────────┬──────────────────┬──────────────┬────────┬──────────────┬─────────┐
         │Magic│Type│   src (16 B)    │   dst (16 B)     │ conn_id (8 B)│len(2 B)│timestamp(4 B)│total(2 B)│
         └────┴────┴──────────────────┴──────────────────┴──────────────┴────────┴──────────────┴─────────┘
          1 B   1 B       16 B               16 B              8 B         2 B        4 B           2 B

         └──────────────────────────────── 50 Bytes insgesamt ────────────────────────────────────┘
```

Jedes Feld hat einen festen Platz — kein Feld ist variabel lang, nichts
muss "gesucht" werden. Das macht das Parsen sehr schnell (nur Offsets
nachschlagen, kein Scannen).

```zig
pub const Header = struct {
    magic: u8,            // Offset 0   - "ist das überhaupt unser Protokoll?"
    packet_type: u8,      // Offset 1   - data / ack / control / err / ...
    src: [16]u8,          // Offset 2   - Absender-Adresse
    dst: [16]u8,          // Offset 18  - Empfänger-Adresse
    conn_id: u64,         // Offset 34  - base_id+seq+flags (siehe fragmentation.zig)
    payload_len: u16,     // Offset 42  - wie lang ist der Payload danach?
    timestamp: u32,       // Offset 44  - Unix-Zeitstempel
    total_fragments: u16, // Offset 48  - wie viele Fragmente hat die Nachricht?
};
```

> **Was hier neu ist:** `total_fragments` (Offset 48-49) gab es vorher
> nicht — der Header war nur 48 Byte groß. Das war die Erweiterung, die
> für den `translation.zig`-Umbau nötig war (siehe dortige Erklärung).

---

## 3. Schreiben: von Struct zu Bytes (`writeHeader`)

```zig
fn writeHeader(buf: []u8, h: Header) void {
    buf[0] = h.magic;
    buf[1] = h.packet_type;
    @memcpy(buf[2..18], &h.src);
    @memcpy(buf[18..34], &h.dst);
    std.mem.writeInt(u64, buf[34..42], h.conn_id, .little);
    std.mem.writeInt(u16, buf[42..44], h.payload_len, .little);
    std.mem.writeInt(u32, buf[44..48], h.timestamp, .little);
    std.mem.writeInt(u16, buf[48..50], h.total_fragments, .little);
}
```

Das ist reines "Feld für Feld an die richtige Stelle kopieren":

```
  Header{ magic=0x4D, packet_type=0x01, src=..., conn_id=12345678, ... }
        │
        ▼  writeHeader()
  buf:  [0x4D][0x01][src: 16 Byte][dst: 16 Byte][conn_id: 8 Byte][len][ts][total]
         ^0    ^1    ^2            ^18           ^34              ^42 ^44 ^48
```

**Warum `.little` (Little-Endian)?** Das ist eine Konvention — beide
Seiten (Sender und Empfänger) müssen sich einig sein, in welcher
Byte-Reihenfolge mehrbytige Zahlen (wie `conn_id: u64`) abgelegt werden.
`.little` heißt: das niedrigstwertige Byte steht zuerst. Solange
`writeHeader` und `readHeader` dieselbe Konvention benutzen (was hier der
Fall ist), spielt es für die Korrektheit keine Rolle, welche man wählt —
nur Konsistenz ist wichtig.

`writeHeader` ist `fn`, nicht `pub fn` — sie ist ein reiner interner
Helfer, den nur `buildPacket` benutzt. Von außerhalb der Datei ist sie
unsichtbar.

---

## 4. Lesen: von Bytes zu Struct (`readHeader`)

Das ist exakt die Umkehrung von `writeHeader`:

```zig
fn readHeader(buf: []const u8) Header {
    var h: Header = undefined;
    h.magic = buf[0];
    h.packet_type = buf[1];
    @memcpy(&h.src, buf[2..18]);
    @memcpy(&h.dst, buf[18..34]);
    h.conn_id = std.mem.readInt(u64, buf[34..42], .little);
    h.payload_len = std.mem.readInt(u16, buf[42..44], .little);
    h.timestamp = std.mem.readInt(u32, buf[44..48], .little);
    h.total_fragments = std.mem.readInt(u16, buf[48..50], .little);
    return h;
}
```

```
  buf:  [0x4D][0x01][src: 16 Byte][dst: 16 Byte][conn_id: 8 Byte][len][ts][total]
         │     │     │             │             │                │    │    │
         ▼     ▼     ▼             ▼             ▼                ▼    ▼    ▼
  Header{ magic=0x4D, packet_type=0x01, src=..., dst=..., conn_id=..., payload_len=..., timestamp=..., total_fragments=... }
```

Auch `readHeader` ist nur intern (`fn`, nicht `pub fn`) — sie wird nur
von `parsePacket` benutzt, das die zusätzliche Sicherheitsprüfung (Magic,
Länge) drumherum baut.

**Wichtig:** `readHeader` selbst prüft **nichts** — sie liest blind die
Bytes an festen Offsets, egal was dort steht. Sie geht implizit davon
aus, dass `buf` mindestens 50 Byte lang ist. Die Prüfung, dass das
wirklich so ist, passiert **vorher**, in `parsePacket` (siehe unten) —
`readHeader` selbst hat kein eigenes Sicherheitsnetz.

---

## 5. `buildPacket` — ein komplettes Paket zusammenbauen

```zig
pub fn buildPacket(
    buf: []u8,
    src: [16]u8,
    dst: [16]u8,
    conn_id: u64,
    ptype: PacketType,
    payload: []const u8,
    total_fragments: u16,
) ![]u8 {
    if (buf.len < HEADER_SIZE + payload.len) return error.BufferTooSmall;

    const ts: u32 = get_unix_time();

    const header = Header{ .magic = MAGIC, .packet_type = @intFromEnum(ptype),
                            .src = src, .dst = dst, .conn_id = conn_id,
                            .payload_len = @intCast(payload.len),
                            .timestamp = ts, .total_fragments = total_fragments };

    writeHeader(buf[0..HEADER_SIZE], header);
    @memcpy(buf[HEADER_SIZE..][0..payload.len], payload);

    return buf[0 .. HEADER_SIZE + payload.len];
}
```

### 5.1 Der wichtigste Punkt zuerst: kein eigener Speicher

```
  buildPacket() alloziert SELBST NICHTS. Der Aufrufer muss schon
  einen ausreichend großen Buffer mitbringen:

  Aufrufer:
  ┌─────────────────────────────────────────────┐
  │ const buf = try allocator.alloc(u8,           │
  │     HEADER_SIZE + payload.len);               │
  │ const pkt = try buildPacket(buf, ...);        │
  └─────────────────────────────────────────────┘

  buildPacket selbst:
  ┌─────────────────────────────────────────────┐
  │ if (buf.len < HEADER_SIZE + payload.len)      │
  │     return error.BufferTooSmall;              │
  │ // schreibt NUR in den übergebenen buf        │
  └─────────────────────────────────────────────┘
```

Das ist ein bewusster Performance-/Kontroll-Trade-off: die Funktion
selbst trifft keine Allokations-Entscheidungen, der Aufrufer hat die
volle Kontrolle darüber, wo der Speicher herkommt (z.B. ein
wiederverwendeter Buffer-Pool statt ständig neu zu allozieren).

### 5.2 Schritt für Schritt

```
  1. Reicht der übergebene buf überhaupt aus?
     NEIN → error.BufferTooSmall (nichts wird angefasst)

  2. Aktuelle Unix-Zeit holen (get_unix_time(), siehe Abschnitt 8)

  3. Ein Header-Struct mit allen Feldern befüllen

  4. writeHeader() schreibt die ersten 50 Byte von buf

  5. @memcpy kopiert den Payload direkt HINTER den Header

  6. Rückgabe: NUR der tatsächlich benutzte Teil von buf
     (buf könnte größer sein als nötig - das Rückgabe-Slice
      schneidet exakt auf Header+Payload-Länge zu)
```

```
  Vorher:                          Nachher (buf, befüllt):
  buf: [??????????????????]        buf: [Header(50B)][Payload][??übrig??]
       (uninitialisiert,                 └─────── pkt (Rückgabewert) ───┘
        ggf. zu groß)
```

### 5.3 Eine Cast-Stelle, die man im Blick haben sollte

```zig
.payload_len = @intCast(payload.len),
```

`payload.len` ist `usize` (auf 64-Bit-Systemen potenziell riesig),
`payload_len` im Header ist `u16` (max. 65535). `@intCast` ist hier ein
**ungeprüfter** Cast — wenn `payload.len > 65535` wäre, gibt es eine
Panik zur Laufzeit statt eines kontrollierten Fehlers. In der Praxis ist
das aktuell ungefährlich, weil `fragmentation.zig` jeden Payload auf
`CHUNK_SIZE` (1200 Byte) begrenzt, bevor er hier ankommt — aber
`buildPacket` selbst verlässt sich darauf, ohne es selbst zu prüfen.
(Mehr dazu in Abschnitt 9.1.)

---

## 6. `parsePacket` — ein empfangenes Paket auseinandernehmen

```zig
pub fn parsePacket(data: []const u8) !ParsedPacket {
    if (data.len < HEADER_SIZE) return error.PacketTooSmall;

    const header = readHeader(data[0..HEADER_SIZE]);

    if (header.magic != MAGIC) return error.InvalidMagic;

    const end = HEADER_SIZE + header.payload_len;
    if (data.len < end) return error.TruncatedPayload;

    return ParsedPacket{ .header = header, .payload = data[HEADER_SIZE..end] };
}
```

Das ist die Gegenrichtung zu `buildPacket`, mit drei Sicherheitschecks
**in genau dieser Reihenfolge**:

```
  rohe Bytes (data)
        │
        ▼
  ┌───────────────────────────────────────┐
  │ Check 1: data.len < HEADER_SIZE ?      │
  │  → zu kurz, um überhaupt einen Header  │
  │    zu enthalten                         │
  │  NEIN → error.PacketTooSmall           │
  └─────────────────┬───────────────────────┘
                     │ ok
                     ▼
  ┌───────────────────────────────────────┐
  │ readHeader() — Felder aus den ersten   │
  │ 50 Byte lesen (blind, ohne Prüfung)    │
  └─────────────────┬───────────────────────┘
                     │
                     ▼
  ┌───────────────────────────────────────┐
  │ Check 2: header.magic != MAGIC ?       │
  │  → ist das überhaupt unser Protokoll,   │
  │    oder zufällige/fremde Bytes?         │
  │  JA → error.InvalidMagic                │
  └─────────────────┬───────────────────────┘
                     │ ok
                     ▼
  ┌───────────────────────────────────────┐
  │ Check 3: data.len < HEADER_SIZE        │
  │           + header.payload_len ?        │
  │  → behauptet der Header einen Payload,  │
  │    der gar nicht vollständig da ist?    │
  │  JA → error.TruncatedPayload            │
  └─────────────────┬───────────────────────┘
                     │ ok
                     ▼
  ParsedPacket{ header, payload: data[50..50+payload_len] }
```

**Wichtiger Punkt zu Check 3:** das schützt davor, dass `payload_len` im
Header größer ist, als tatsächlich an Bytes vorhanden ist (z.B. weil das
Paket auf der Leitung abgeschnitten wurde, oder weil jemand absichtlich
einen zu großen `payload_len`-Wert in den Header geschrieben hat). Ohne
diesen Check würde `data[HEADER_SIZE..end]` mit einem `end` jenseits von
`data.len` zugreifen — das wäre ein Out-of-Bounds-Crash.

### 6.1 Wo ist die Stelle, wo `translation.zig` einsteigt?

```
  In translation.zig::decryptFragment wird ERST entschlüsselt,
  DANN erst (in translateInbound) parsePacket() aufgerufen:

  rohe verschlüsselte Bytes
        │
        ▼
  decryptFragment()  ──► entschlüsselte Bytes
        │
        ▼
  header.parsePacket()  ──► ParsedPacket{ header, payload }
        │
        ▼
  frag.decodeConnId(parsed.header.conn_id)  ──► base_id, seq
```

`header.zig` selbst weiß nichts von Verschlüsselung — es bekommt von
`translation.zig` bereits entschlüsselte Bytes und parst die wie jeden
anderen Bytestream.

---

## 7. `ParsedPacket` — das Rückgabe-Struct

```zig
pub const ParsedPacket = struct {
    header: Header,
    payload: []const u8,
};
```

```
  ParsedPacket ist nur ein Container für zwei Dinge:
  - header: alle Felder als Struct (leicht zugreifbar, z.B. .conn_id)
  - payload: ein SLICE in die Original-Bytes (data), KEINE Kopie!

  data: [Header (50 B)][Payload-Bytes................]
                         └──── payload zeigt genau hierhin ────┘
                              (kein extra Speicher alloziert)
```

Das ist speichereffizient — `payload` kopiert nichts, sondern ist nur
ein "Fenster" in die schon vorhandenen `data`-Bytes. Das bedeutet aber
auch: **`payload` ist nur so lange gültig, wie `data` selbst gültig
bleibt.** Wird `data` freigegeben, während `payload` noch irgendwo
benutzt wird, zeigt `payload` auf ungültigen Speicher.

---

## 8. Die `get_unix_time`-Anbindung an C

```zig
extern fn get_unix_time() u32;
```

```
  header.zig  ──extern fn Aufruf──►  time.c (separat kompiliert)
                                       #include <time.h>
                                       uint32_t get_unix_time(void) {
                                           return (uint32_t)time(NULL);
                                       }
```

`extern fn` heißt: Zig kennt nur die **Signatur** dieser Funktion (nimmt
keine Argumente, gibt `u32` zurück), aber nicht ihre Implementierung.
Die echte Implementierung kommt aus einer separat kompilierten C-Datei,
die beim Bauen mitgelinkt werden muss:

```
zig run src/header.zig -lc src/time.c
zig test src/header.zig -lc src/time.c
```

Fehlt `time.c` beim Linken, bekommt man einen Linker-Fehler
(`undefined symbol: get_unix_time`) — das Programm kompiliert zwar als
Zig-Code, aber das fertige Binary lässt sich nicht bauen, weil die
Funktion nirgendwo tatsächlich definiert ist.

**Warum überhaupt C für sowas Simples?** Das ist wahrscheinlich aus
einer Übergangsphase / einem früheren Zig-Stand übernommen, in der die
Standardbibliothek das nicht so leicht direkt anbot. Mehr dazu in
Abschnitt 9.2.

---

## 9. Was man noch ändern/ergänzen könnte

### 9.1 `payload_len`/`@intCast` hat kein eigenes Sicherheitsnetz

`buildPacket` castet `payload.len` (usize) ungeprüft nach `u16`. Aktuell
ist das in der Praxis sicher, weil `fragmentation.zig` den Payload immer
auf `CHUNK_SIZE` (1200 Byte) begrenzt, bevor `buildPacket` aufgerufen
wird — aber `header.zig` selbst erzwingt das nicht. Wenn `buildPacket`
jemals direkt (ohne den Umweg über `fragmentation.zig`) mit einem zu
großen Payload aufgerufen würde, gäbe es eine Laufzeit-Panik statt eines
kontrollierten Fehlers. Ein expliziter Check (`if (payload.len > std.math.maxInt(u16)) return error.PayloadTooLarge;`) direkt in `buildPacket`
würde diese Funktion in sich abgeschlossen sicher machen, statt sich auf
die Disziplin der Aufrufer zu verlassen.

### 9.2 `get_unix_time` über C — native Zig-Alternative verfügbar

Wie schon in der `translation.zig`-Erklärung erwähnt: Zig 0.16 bietet
mit `std.Io.Timestamp` eine Möglichkeit, die aktuelle Zeit direkt in Zig
zu bekommen, ohne C-Code zu linken. Das würde:
- den Build vereinfachen (kein `-lc src/time.c` mehr bei jedem
  `zig run`/`zig test`/`zig build`)
- eine externe Abhängigkeit (C-Toolchain für diese eine Datei) entfernen

Das wäre eine Änderung an `header.zig` selbst (die `extern fn`-Deklaration
und der Aufruf in `buildPacket` müssten ersetzt werden), die ich nicht
einfach umsetze, ohne dass du das explizit willst — aber technisch ist
sie problemlos möglich.

### 9.3 Kein Versions-/Kompatibilitätsfeld im Header

Der Header hat ein `magic`-Byte (ist es überhaupt dieses Protokoll?),
aber kein separates Versionsfeld (ist es **welche Version** dieses
Protokolls?). Wenn sich das Header-Layout später nochmal ändert (so wie
gerade beim Hinzufügen von `total_fragments`), gibt es aktuell keine
Möglichkeit für einen Empfänger, zwischen "altem Header ohne
`total_fragments`" und "neuem Header mit `total_fragments`" zu
unterscheiden — beide haben dasselbe `magic`-Byte. Für ein Protokoll,
das sich noch weiterentwickelt, wäre ein zusätzliches `version: u8`-Feld
(z.B. direkt nach `magic`) eine Möglichkeit, zukünftige Layout-Änderungen
sauberer zu handhaben, ohne dass alte und neue Implementierungen sich
gegenseitig falsch interpretieren.

### 9.4 `timestamp` hat keine festgelegte Bedeutung/Prüfung

Das `timestamp`-Feld wird beim Bauen gesetzt (`get_unix_time()`), aber
beim Parsen (`parsePacket`) nirgendwo geprüft oder verwendet. Es ist
unklar, wofür es gedacht ist:
- Reine Debugging-/Logging-Information?
- Schutz gegen Replay-Angriffe (ein altes, aufgezeichnetes Paket nochmal
  einspielen)?

Falls Replay-Schutz beabsichtigt ist, müsste der Empfänger den
Zeitstempel aktiv gegen ein Zeitfenster prüfen (z.B. "Pakete älter als
30 Sekunden ablehnen") — das passiert aktuell nirgendwo. Falls es nur
Debugging-Information ist, wäre das auch gut, explizit als Kommentar im
Code festzuhalten, damit niemand später fälschlich davon ausgeht, dass
dieses Feld schon einen Sicherheitszweck erfüllt.

### 9.5 `u32`-Timestamp läuft 2106 über

`timestamp: u32` als Unix-Zeitstempel (Sekunden seit 1970) läuft am
7. Februar 2106 über (Year-2106-Problem, das `u32`-Äquivalent zum
Year-2038-Problem bei `i32`). Das ist aktuell kein praktisches Problem,
aber falls dieses Protokoll sehr langlebig sein soll, wäre `u32` mit
einem ferneren Bezugspunkt (statt Unix-Epoche) oder direkt `i64`/`u64`
eine zukunftssicherere Wahl. Reine Erwähnung der Vollständigkeit halber —
in den allermeisten praktischen Szenarien irrelevant.

### 9.6 `main()` ist Debug-/Beispielcode, kein Teil der eigentlichen Bibliothek

Die `main`-Funktion am Ende liest eine Datei (`../dump/linux.svg`) und
baut/parst damit ein Beispielpaket. Das ist nützlich zum manuellen
Ausprobieren (`zig run src/header.zig`), hat aber zwei Eigenheiten, die
erwähnenswert sind:
- Der hartkodierte Pfad `../dump/linux.svg` existiert wahrscheinlich nur
  auf deinem Entwicklungsrechner — für jeden anderen, der das Repo
  klont, schlägt `zig run src/header.zig` mit einem Datei-nicht-gefunden-
  Fehler fehl, falls diese Datei nicht mitkommt.
- Sobald `header.zig` über eine `build.zig` oder als importiertes Modul
  eingebunden wird (statt direkt mit `zig run`), wird diese `main`-
  Funktion ohnehin nie aufgerufen — sie ist reiner Ad-hoc-Testcode. Es
  könnte sich lohnen, sie irgendwann durch echte `test`-Blöcke zu
  ersetzen oder zu ergänzen (wie wir das in `translation.zig` und
  `fragmentation.zig` schon gemacht haben), damit `zig test
  src/header.zig` auch hier etwas Sinnvolles prüft, statt nur "0 of 0
  tests passed" zu melden.

---

## 10. Kurz zusammengefasst

```
  buildPacket:   Felder (Struct) → in vom Aufrufer bereitgestellten
                 Buffer schreiben → Header+Payload als []u8 zurückgeben
                 (alloziert selbst nichts)

  parsePacket:   rohe Bytes → 3 Sicherheitschecks (Länge, Magic,
                 Payload-Vollständigkeit) → Header als Struct +
                 Payload als Slice in die Original-Bytes

  Kernidee:      header.zig kennt nur "wie sehen die Bytes aus" -
                 nichts über Verschlüsselung (translation.zig) oder
                 Fragmentierung (fragmentation.zig). Reine, isolierte
                 Byte-Buchhaltung mit fester Feldgröße pro Position.
```