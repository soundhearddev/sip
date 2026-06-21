// keyexchange.zig — X25519-Schluesselaustausch, komplett isoliert.
//
// Bewusst MODULAR gehalten: diese Datei kennt nichts von Sockets oder von
// SIP/translation.zig. Sie nimmt einen empfangenen Public Key vom Peer und
// den eigenen geheimen Schluessel entgegen und liefert den abgeleiteten
// symmetrischen Schluessel zurueck. Wer das Schluesselaustausch-Verfahren
// spaeter komplett ersetzen will (z.B. echtes mutual auth, ein anderes
// Curve-Verfahren, oder vorerst wieder ein simples geteiltes Passwort wie
// in den fruehen translation.zig-Tests), muss NUR diese Datei anfassen -
// main.zig ruft nur die drei Funktionen unten auf und kennt keine
// X25519-Details.
//
// Verfahren: dasselbe Prinzip wie TLS 1.3 fuer den Schluesselaustausch
// (ECDHE mit X25519), nur ohne den TLS-Record-Layer und Zertifikats-Stack
// drumherum. Aus dem X25519-Shared-Secret wird per HKDF-SHA256 ein
// 32-Byte-Schluessel abgeleitet, der direkt als ChaCha20-Poly1305-Key fuer
// translation.zig::encryptFragment/decryptFragment dient.

const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const PUBLIC_KEY_SIZE: usize = X25519.public_length;
pub const SECRET_KEY_SIZE: usize = X25519.secret_length;
pub const DERIVED_KEY_SIZE: usize = 32; // passt zu translation.zig::KEY_SIZE

pub const KeyExchangeError = error{
    InvalidPeerPublicKey,
};

pub const LocalKeyPair = struct {
    secret_key: [SECRET_KEY_SIZE]u8,
    public_key: [PUBLIC_KEY_SIZE]u8,
};

/// Erzeugt ein frisches X25519-Schluesselpaar. Der geheime Schluessel kommt
/// direkt aus einer kryptographisch sicheren Quelle (std.Io.randomSecure) -
/// bewusst NICHT aus einem KeyPair.generate()-Komfort-Aufruf, da dessen
/// Signatur sich zwischen Zig-Versionen schon mehrfach geaendert hat
/// (z.B. Ed25519.KeyPair.generate brauchte ploetzlich ein io-Argument).
/// Der hier genutzte Weg (Zufallsbytes + scalarmult) ist der stabile,
/// von solchen API-Verschiebungen unabhaengige Kern.
pub fn generateLocalKeyPair(io: std.Io) !LocalKeyPair {
    var secret_key: [SECRET_KEY_SIZE]u8 = undefined;
    try std.Io.randomSecure(io, &secret_key);

    const public_key = try X25519.recoverPublicKey(secret_key);

    return LocalKeyPair{
        .secret_key = secret_key,
        .public_key = public_key,
    };
}

/// Leitet aus dem eigenen geheimen Schluessel und dem empfangenen
/// Public Key des Peers den gemeinsamen symmetrischen Schluessel ab.
/// Client und Server rufen das mit vertauschten Rollen auf und erhalten
/// denselben DERIVED_KEY_SIZE-Byte-Schluessel (Eigenschaft von
/// Diffie-Hellman: scalarmult(a_secret, b_public) == scalarmult(b_secret, a_public)).
pub fn deriveSharedKey(
    local: LocalKeyPair,
    peer_public_key: [PUBLIC_KEY_SIZE]u8,
) KeyExchangeError![DERIVED_KEY_SIZE]u8 {
    const shared_secret = X25519.scalarmult(local.secret_key, peer_public_key) catch {
        // IdentityElementError von X25519.scalarmult bedeutet: der peer_public_key
        // war ungueltig (z.B. ein Low-Order-Punkt). Das hier NICHT als Crash
        // durchlassen, sondern als klar benannten Fehler - ein bewusst oder
        // versehentlich kaputter Public Key darf nicht zu einem schwachen
        // oder vorhersagbaren Shared Secret fuehren.
        return error.InvalidPeerPublicKey;
    };

    // Das rohe X25519-Shared-Secret direkt als Schluessel zu nutzen ist NICHT
    // empfohlen (es ist nicht gleichverteilt genug fuer direkte Verwendung
    // als symmetrischer Schluessel) - HKDF macht daraus einen sauberen,
    // gleichverteilten 32-Byte-Schluessel. "sip-tcp-test" als Info-String
    // trennt diesen Anwendungsfall von anderen, falls derselbe Code-Pfad
    // spaeter fuer andere Zwecke wiederverwendet wird.
    var derived_key: [DERIVED_KEY_SIZE]u8 = undefined;
    const prk = HkdfSha256.extract(&.{}, &shared_secret);
    HkdfSha256.expand(&derived_key, "sip-tcp-test", prk);

    return derived_key;
}
