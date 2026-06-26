# Chunk-Reassembly Konzept für translation.zig

## Überblick

`fragmentation.zig` (Sender) teilt große Payloads in ≤16 MiB Chunks und sendet sie als
einzelne Pakete mit `command = .DataChunk` (außer dem letzten: `command = .DataEnd`),
jeweils mit derselben `conn_id` und aufsteigender `seq_num`.

`translation.zig` (Empfänger) muss diese Chunks wieder zu einer vollständigen Datei
zusammensetzen — **ohne** den gesamten Inhalt im RAM zu halten.

## Datenfluss (Empfänger-Seite)

```
                    ┌─────────────────────────────────────┐
                    │         readInboundPacket()          │
                    │   (bestehend, unverändert)            │
                    │   - parsed outer + inner header       │
                    │   - entschlüsselt Payload              │
                    └───────────────┬───────────────────────┘
                                    │ InboundPacket { parsed, _buf }
                                    ▼
                    ┌─────────────────────────────────────┐
                    │      Reassembler.feed(packet)         │  <- NEU
                    └───────────────┬───────────────────────┘
                                    │
                  ┌─────────────────┼─────────────────────┐
                  ▼                 ▼                     ▼
           command == .Data   command == .DataChunk   command == .DataEnd
                  │                 │                     │
                  ▼                 ▼                     ▼
         sofort fertig,      Chunk-Datei auf Disk    letzter Chunk schreiben,
         kein Reassembly      schreiben               dann alle Chunk-Dateien
         nötig                (siehe unten)            zusammenfügen -> fertig
```

## Speicherung der Chunks auf Disk

Pro `(conn_id, seq_num)` wird eine eigene Temp-Datei angelegt:

```
/tmp/sip/<conn_id>/<seq_num>.chunk
```

- `conn_id` (u64) als Verzeichnisname (hex-formatiert), damit mehrere parallele
  Transfers sich nicht in die Quere kommen.
- `seq_num` (u32) als Dateiname → Reihenfolge ist über den Dateinamen klar,
  kein Sortieren der Chunks im Speicher nötig.
- Jeder Chunk wird **sofort** beim Empfang auf Disk geschrieben und der entschlüsselte RAM-Buffer direkt
  wieder freigegeben (`freeInboundPacket`).


## Reassembly-Zustand (im RAM, klein)

Pro aktivem Transfer wird **nicht** der Payload, sondern nur Metadaten im RAM gehalten:

```zig
const TransferState = struct {
    conn_id: u64,
    highest_seq_seen: u32,
    chunk_count: u32,
    // kein Payload-Buffer
};
```

Diese States werden in einer `std.AutoHashMap(u64, TransferState)` verwaltet, key = `conn_id`.
Das ist winzig (ein paar Bytes pro aktivem Transfer), unabhängig von der Dateigröße.

**Wer hält diese HashMap?**
→ Der Aufrufer (z.B. `runServer` in svr_clt_test.zig) hält eine `Reassembler`-Instanz
und ruft `.feed(packet)` für jedes eingehende Paket auf. `translation.zig` stellt den
*Typ* `Reassembler` und seine Methoden bereit, aber der Lebenszyklus (init/deinit)
liegt beim Server-Loop — passt zu deiner Aussage, dass die eigentliche
Transfer-Orchestrierung eher Aufgabe des "sip-daemon"-Layers ist.

## Ablauf bei `.DataChunk`

1. `Reassembler.feed(packet)` wird aufgerufen.
2. Falls `conn_id` neu ist → neuen `TransferState` anlegen, Verzeichnis
   `/tmp/sip-reassembly/<conn_id>/` erstellen.
3. Optional: Plausibilitätscheck `seq_num == state.highest_seq_seen + 1`
   (Warnung/Error bei Lücke oder Duplikat, aber kein Hard-Crash nötig,
   da TCP-Reihenfolge ohnehin garantiert ist – siehe frühere Diskussion).
4. Payload des Pakets in `<conn_id>/<seq_num>.chunk` schreiben.
5. RAM-Buffer des Pakets sofort freigeben.
6. `state.highest_seq_seen = seq_num`, `state.chunk_count += 1`.

## Ablauf bei `.DataEnd`

1. Letzten Chunk-Payload genauso wie `.DataChunk` auf Disk schreiben.
2. Alle Dateien `<conn_id>/0.chunk`, `<conn_id>/1.chunk`, ... `<conn_id>/N.chunk`
   in aufsteigender Reihenfolge lesen und **gestreamt** (kleine Buffer, nicht alles
   auf einmal in den RAM) an die finale Ziel-Datei anhängen.
3. Temp-Verzeichnis `/tmp/sip-reassembly/<conn_id>/` löschen.
4. `TransferState` aus der HashMap entfernen.
5. Aufrufer (Server) bekommt Bescheid "Transfer komplett, finale Datei liegt unter X".

## Ablauf bei `.Data` (unverändert, kein Chunking)

Einfach wie bisher: Paket kommt, Payload ist komplett, fertig — kein Reassembler-Zustand
nötig, `Reassembler.feed()` gibt sofort "complete" mit dem Payload zurück, ohne
irgendwas auf Disk zu zwischenspeichern.

## Offene Punkte, die wir noch klären sollten

1. **Wohin zeigt die finale Ziel-Datei?** Wird das dem `Reassembler` beim `init`
   mitgegeben (ein `output_path`), oder erst bei `.DataEnd` vom Aufrufer entschieden?
2. **Was, wenn eine Verbindung mitten im Transfer abbricht?** Bleiben Temp-Dateien
   liegen (Cleanup-Strategie)?
3. **Mehrere parallele Transfers über denselben Server-Prozess?** Falls dein Server
   aktuell nur eine einzelne Verbindung (`accept` einmal) annimmt, ist das erstmal
   kein Thema — aber die `conn_id`-Trennung macht es zukunftssicher.
4. **API-Form**: Reicht dir `Reassembler.feed(packet) -> FeedResult` wobei
   `FeedResult` ein Tagged Union `{ pending, complete: []const u8 (path) }` ist?