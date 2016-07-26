package memlo.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;

import org.junit.Test;

public class EncodingUtilsTest {

    @Test
    public void encodingUUIdAsBytes_byteArraySizeRight() {
        UUID uuid = UUID.randomUUID();

        byte[] result = EncodingUtils.asBytes(uuid);

        assertThat(result.length).isEqualTo(16);
    }

    @Test
    public void asBytesAsUUID_generatesSameUUID() {
        UUID uuid = UUID.randomUUID();

        byte[] bytes = EncodingUtils.asBytes(uuid);
        UUID reconstructedUuid = EncodingUtils.asUUID(bytes);

        assertThat(reconstructedUuid).isEqualTo(uuid);
    }
}
