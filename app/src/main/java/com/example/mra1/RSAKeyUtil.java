package com.example.mra1;

import android.content.res.Resources;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class RSAKeyUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String readPublicKeyFromCrtFile(Resources res) {
        try {
            InputStream publicKeyInputStream = res.openRawResource(R.raw.mra_pub_key);  // Replace with your .crt file name

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            int data;
            while ((data = publicKeyInputStream.read()) != -1) {
                byteArrayOutputStream.write(data);
            }
            byteArrayOutputStream.flush();

            return byteArrayOutputStream.toString(StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String generateAndExportRSAPublicKeyPem(Resources res) {
        try {
            String publicKeyPem = readPublicKeyFromCrtFile(res);

            if (publicKeyPem != null) {
                return publicKeyPem;
            } else {
                return "Error reading public key";
            }
        } catch (Exception e) {
            e.printStackTrace();
            return "Error generating public key";
        }
    }


    private static String publicKeyToPem(PublicKey publicKey) throws IOException {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        PemObject pemObject = new PemObject("PUBLIC KEY", x509EncodedKeySpec.getEncoded());

        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();

        return stringWriter.toString();
    }
}
