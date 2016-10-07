package memlo.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;

public class KeyTranscoderTest {

    private String secret = "victoria's secret";
    private KeyPair pair;
    private Signer signer = Signer.getInstance();

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        this.pair = new KeyPairFactory().createKey();
    }

    @Test
    public void encode_decodencodeSecretKey_secret() {
        byte[] data = Signer.getInstance().digestRaw("mysecret");
        SecretKey original = KeyTranscoder.encodeSecretKey(data);
        String keyEncoded = KeyTranscoder.encodeKey(original);
        SecretKey decoded = KeyTranscoder.decodeSecretKey(keyEncoded);

        assertThat(original).isEqualTo(decoded);

        data = Signer.getInstance().digestRaw("otherSecret");
        SecretKey other = KeyTranscoder.encodeSecretKey(data);

        assertThat(original).isNotEqualTo(other);
    }

    @Test
    public void secret_signEncodeDecodeKeySignAgain_equals() {
        String[] data = {"hello", "World"};
        String signedOriginal = signer.hmac(this.secret, data);

        String signedDecoded = signer.hmac(this.secret, data);
        assertThat(signedOriginal).isEqualTo(signedDecoded);
    }

    @Test
    public void publicKey_signEncodeDecodePublicKeyVerify_ok() {
        String[] data = {"hello", "World"};
        String signedData = signer.sign(this.pair.getPrivate(), data);

        String encodedPublicKey = KeyTranscoder.encodeKey(this.pair.getPublic());
        PublicKey publicKey = KeyTranscoder.decodePublicKey(encodedPublicKey);

        assertThat(signer.verify(publicKey, signedData, data)).isTrue();
    }

    @Test
    public void privateKey_signEncodeDecodePublicKeyVerify_ok() {
        String encodedPrivateKey = KeyTranscoder.encodeKey(this.pair.getPrivate());
        PrivateKey privateKey = KeyTranscoder.decodePrivateKey(encodedPrivateKey);

        String[] data = {"hello", "World"};
        String signedData = signer.sign(privateKey, data);

        assertThat(signer.verify(this.pair.getPublic(), signedData, data)).isTrue();
    }
}
