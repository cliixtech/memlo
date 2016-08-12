package memlo.security;

import java.security.Security;

public class Initializer {

    private static boolean initialized = false;

    public static void init() {
        if (!initialized) {
            Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
        }
    }
}
