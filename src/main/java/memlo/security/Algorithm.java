package memlo.security;

public enum Algorithm {
    SECRET_KEY("DESede"),
    KEY_PAIR("ECDSA"),
    KEY_PAIR_PROVIDER("SC"),
    KEY_PAIR_SPEC("secp256k1"),
    KEY_PAIR_SIGN("SHA256withECDSA"),
    HMAC("HmacSHA256"),
    DIGEST("MD5");

    public final String algm;

    Algorithm(String algm) {
        this.algm = algm;
    }
}
