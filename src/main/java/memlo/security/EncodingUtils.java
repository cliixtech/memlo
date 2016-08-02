package memlo.security;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.UUID;

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

    public static byte[] asBytes(UUID uuid) {
        ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());

        return bb.array();
    }

    public static UUID asUUID(byte[] bytes) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        Long high = byteBuffer.getLong();
        Long low = byteBuffer.getLong();

        return new UUID(high, low);
    }
}
