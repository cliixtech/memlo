package memlo.security;

public enum Algorithm {
    SECRET_KEY("DESede"),
    KEY_PAIR("EC"),
    KEY_PAIR_SIGN("SHA256withECDSA"),
    HMAC("HmacSHA256"), DIGEST("MD5");

    public final String algm;

    Algorithm(String algm) {
        this.algm = algm;
    }
}
