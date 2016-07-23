package memlo.security;

import java.io.IOException;

import net.iharder.Base64;

public class EncodingUtils {

    public static String asString(byte[] raw) {
        return Base64.encodeBytes(raw);
    }

    public static byte[] asBytes(String encoded) {
        try {
            return Base64.decode(encoded);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
