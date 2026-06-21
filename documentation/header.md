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
         ┌────┬────┬──────────────────┬──────────────────┬──────────────┐
         │Magic│Type│   src (16 B)    │   dst (16 B)     │ conn_id (8 B)│
         └────┴────┴──────────────────┴──────────────────┴──────────────┘
          1 B   1 B       16 B               16 B              8 B           

         └──────────────────── 42 Bytes insgesamt ──────────────────────┘
```

```zig
pub const Header = struct {
    magic: u8,            // Offset 0   - "ist das überhaupt unser Protokoll?"
    packet_type: u8,      // Offset 1   - data / ack / control / err / ...
    src: [16]u8,          // Offset 2   - Absender-Adresse
    dst: [16]u8,          // Offset 18  - Empfänger-Adresse
    conn_id: u64,         // Offset 34  - base_id+seq+flags 
};
```



## 3. Schreiben: von Struct zu Bytes (`writeHeader`)

```zig
fn writeHeader(buf: []u8, h: Header) void {
    buf[0] = h.magic;
    buf[1] = h.packet_type;

    @memcpy(buf[2..18], &h.src);
    @memcpy(buf[18..34], &h.dst);

    std.mem.writeInt(u64, buf[34..42], h.conn_id, .little);
}
```

Das ist reines "Feld für Feld an die richtige Stelle kopieren":

```
  Header{ magic=0x4D, packet_type=0x01, src=..., ... }
        │
        ▼  writeHeader()
  buf:  [0x4D][0x01][src: 16 Byte][dst: 16 Byte][conn_id: 8 Byte]
        ^0    ^1    ^2            ^18           ^34             ^42 
```



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

    return h;
}
```






## 5. `buildPacket` — ein komplettes Paket zusammenbauen

```zig
pub fn buildPacket(
    buf: []u8,
    src: [16]u8,
    dst: [16]u8,
    conn_id: u64,
    ptype: PacketType,
    payload: []const u8,
) ![]u8 {
    if (buf.len < HEADER_SIZE + payload.len) return error.BufferTooSmall;

    const header = Header{
        .magic = MAGIC,
        .packet_type = @intFromEnum(ptype),
        .src = src,
        .dst = dst,
        .conn_id = conn_id,
    };

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

  4. writeHeader() schreibt die ersten 42 Byte von buf

  5. @memcpy kopiert den Payload direkt HINTER den Header

  6. Rückgabe: NUR der tatsächlich benutzte Teil von buf
     (buf könnte größer sein als nötig - das Rückgabe-Slice
      schneidet exakt auf Header+Payload-Länge zu)
```

```
  Vorher:                          Nachher (buf, befüllt):
  buf: [??????????????????]        buf: [Header(42B)][Payload][??übrig??]
       (uninitialisiert,                 └─────── pkt (Rückgabewert) ───┘
        ggf. zu groß)
```



## 6. `parsePacket` — ein empfangenes Paket auseinandernehmen

```zig
pub fn parsePacket(data: []const u8) !ParsedPacket {
    if (data.len < HEADER_SIZE) return error.PacketTooSmall;

    const header = readHeader(data[0..HEADER_SIZE]);

    if (header.magic != MAGIC) return error.InvalidMagic;

    return ParsedPacket{
        .header = header,
        .payload = data[HEADER_SIZE..],
    };
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
  │ 42 Byte lesen (blind, ohne Prüfung)    │
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
  ParsedPacket{}
```

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



---

## 7. `ParsedPacket` — das Rückgabe-Struct

```zig
pub fn parsePacket(data: []const u8) !ParsedPacket {
    if (data.len < HEADER_SIZE) return error.PacketTooSmall;

    const header = readHeader(data[0..HEADER_SIZE]);

    if (header.magic != MAGIC) return error.InvalidMagic;

    return ParsedPacket{
        .header = header,
        .payload = data[HEADER_SIZE..],
    };
}
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


```
zig run src/header.zig -lc src/time.c
zig test src/header.zig -lc src/time.c
```

Fehlt `time.c` beim Linken, bekommt man einen Linker-Fehler
(`undefined symbol: get_unix_time`) — das Programm kompiliert zwar als
Zig-Code, aber das fertige Binary lässt sich nicht bauen, weil die
Funktion nirgendwo tatsächlich definiert ist.




## 9. Kurz zusammengefasst

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