Schicht-für-Schicht Abgleich
1. Adressformat — session.zig::peerMeshAddr() und address.zig/utils.zig::generateAddress()

Problem gefunden: Es gibt zwei widersprüchliche Adresssysteme im Code:

session.zig: mesh_addr = SHA256(ed25519_pubkey) → 32 Byte, deterministisch, kryptografisch verifizierbar — das ist die "richtige" SIP-Adresse nach deiner eigenen Definition von letztens.
address.zig/utils.zig: generateAddress() würfelt eine zufällige IPv6-Suffix-Adresse basierend auf der Unixzeit als RNG-Seed, völlig unabhängig vom Public Key. Das ist eher "IPv6-Adress-Rotation für Anonymität auf der physischen NIC" — eine ganz andere Funktion, die mit deinem eigentlichen "Identität → Adresse"-Prinzip nichts zu tun hat.

Das sind zwei verschiedene Adressräume, die im Code nirgends verbunden werden. Wenn address.zig "die" SIP-Adresse sein soll, bricht das dein eigenes Prinzip (Adresse = Funktion des Public Keys). Wenn es nur eine Hilfsfunktion für die IPv6-Translation-Schicht ist (also Teil von Punkt 3, nicht Punkt 1), ist der Name/die Doku irreführend.
2. Paketformat — header.zig

Sauber: 48-Byte-Header, fester Byte-Layout, dokumentiert per Kommentar, MAGIC-Byte zur Validierung. Entspricht der Regel.
Aber: header.zig Zeile 16-22 sagt src/dst sind [16]u8 (16 Byte), während session.zig::peerMeshAddr und trust.zig::PeerInfo.mesh_addr [32]u8 (32 Byte, voller SHA256) verwenden. Direkter Typkonflikt zwischen Header und Adressschicht — der Header kann eine volle Mesh-Adresse gar nicht aufnehmen, nur die erste Hälfte. Das ist entweder ein Bug oder eine bewusste Adress-Trunkierung, die aber nirgends dokumentiert/spezifiziert ist (welche 16 von 32 Byte? erste Hälfte? Hash-Truncation mit eigenen Kollisionseigenschaften?).
3. Translation/Encapsulation-Regel — translation.zig

Strukturell sauber: ChaCha20-Poly1305 AEAD über Header (als AAD) + Payload, mit Nonce + Tag. Entspricht der Regel als Verschlüsselungsschicht.
Aber: das ist Transport-Verschlüsselung über TCP, nicht "Translation in IPv6". Du hattest die Kernidee definiert als "Translation Layer der Zugriff auf ein Overlay über IPv6 erlaubt" — sprich Encapsulation von SIP-Paketen in IPv6 (wie WireGuard/6in4). Was hier tatsächlich implementiert ist: ein TCP-Stream-Protokoll (server.zig öffnet std.Io.net TCP-Listener auf Port 9871/9872), bei dem SIP-Pakete als Payload über eine normale TCP-Verbindung laufen. Es gibt keinen Code, der ein SIP-Paket tatsächlich in ein rohes IPv6-Paket einbettet (kein Raw-Socket, kein IPv6-Extension-Header, kein IP-in-IP-Tunneling). Das ist im Moment eher "ein eigenes Protokoll über TCP/IP" als "ein Protokoll, das IPv6 als Transport-Substrat für ein eigenes Adresssystem nutzt".
4. Trust/Verifikation — trust.zig + session.zig

Sauber: Ed25519-Signaturen für Challenge-Response (signChallenge/verifyChallenge), Invite-Ketten mit InviteToken, TrustStore. Entspricht der Regel.
5. Discovery/Bootstrap — bootstrap.zig + server.zig::listenBootstrap

Sauber als Konzept: Bootstrap-Port (9871) getrennt von Daten-Port (9872), Approval-Flow. Entspricht der Regel in der Grundidee.
Aber: Das ist aktuell kein Discovery, sondern direktes Verbinden zu einer bekannten IP-Adresse (bootstrap.zig Zeile 14: host = argv[1] — der Nutzer gibt eine IP/Hostname direkt an). Echtes "Discovery" würde bedeuten: gegeben eine SIP-Adresse, finde die IP, die aktuell dahintersteckt (z.B. via DHT). Das fehlt komplett — es gibt keine Zuordnung mesh_addr → aktuelle IP. Aktuell muss man die IP bereits kennen, was Hand-in-Hand mit Punkt 1 hängt (das Adresssystem hat aktuell keine Funktion, weil nichts danach auflöst).
Was inkonsistent bzw. ungeklärt ist (Kurzfassung)
#ProblemWo1Zwei unabhängige, sich widersprechende Adresssysteme (zufällige IPv6 vs. SHA256(pubkey))address.zig/utils.zig vs. session.zig2Header nimmt 16 Byte Adressen, Mesh-Adresse ist aber 32 Byteheader.zig vs. session.zig/trust.zig3"Translation" ist aktuell TCP-Payload-Verschlüsselung, keine IPv6-Encapsulationtranslation.zig/server.zig4Kein Mechanismus, der SIP-Adresse → IP auflöst (Discovery fehlt)gesamtes Bootstrap-System5fragmentation.zig kodiert seq in nur 24 Bit (>> 32 & 0x00FFFFFF), aber conn_id Doku in header.zig sagt 8 Byte ohne Subfeld-Aufteilung — die Bitaufteilung ist nirgends im Header-Kommentar dokumentiertfragmentation.zig vs. header.zig-Kommentar
Was noch komplett fehlt, wenn man die Spec aus meiner letzten Antwort ernst nimmt: kein Raw-IPv6-Send/Receive irgendwo im Code — alles läuft über std.Io.net TCP-Streams. Falls "Translation Layer über IPv6" wörtlich gemeint ist (eigene Pakete direkt in IPv6 statt in TCP), fehlt diese Schicht komplett — aktuell ist es ein TCP-basiertes Overlay-Protokoll, kein IP-Tunneling-Protokoll.
