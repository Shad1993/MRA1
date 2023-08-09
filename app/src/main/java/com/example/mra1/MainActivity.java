package com.example.mra1;

import android.content.res.Resources;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import android.os.AsyncTask;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {

    private TextView textViewResult;
    private static final String TAG = "EncryptionActivity";
    private class SendPayloadTask extends AsyncTask<String, Void, String> {
        @Override
        protected String doInBackground(String... params) {
            String encryptedPayload = params[0];

            try {
                // Construct the JSON request body
                JSONObject requestBody = new JSONObject();
                requestBody.put("requestId", "20230324213055"); // Replace with your request ID
                requestBody.put("payload", encryptedPayload);

                OkHttpClient client = new OkHttpClient();

                MediaType mediaType = MediaType.parse("application/json");
                RequestBody body = RequestBody.create(mediaType, requestBody.toString());

                Request request = new Request.Builder()
                        .url("https://vfisc.mra.mu/einvoice-token-service/token-api/generate-token")
                        .addHeader("Content-Type", "application/json")
                        .addHeader("username", "LBatour")
                        .addHeader("ebsMraId", "16887088519063EJ7S0ZS109")
                        .post(body)
                        .build();

                Response response = client.newCall(request).execute();
                if (response.isSuccessful()) {
                    return response.body().string();
                } else {
                    return "Error response code: " + response.code();
                }
            } catch (Exception e) {
                e.printStackTrace();
                return "Request Failed: " + e.getMessage();
            }
        }

        @Override
        protected void onPostExecute(String result) {
            textViewResult.setText("Response:\n" + result);
        }
    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        textViewResult = findViewById(R.id.publicKeyTextView);

        try {
            String payload = "{\n" +
                    " \"username\": \"LBatour\",\n" +
                    " \"password\": \"Logi159753@\",\n" +
                    " \"encryptKey\": \"jCH3gDAWhw9+oYdPDdRyvwL/VPihgWeHH0Uvc2rQ8SU=\",\n" +
                    " \"refreshToken\": \"false\"\n" +
                    "}";


            Resources res = getResources();
            InputStream certificateInputStream = res.openRawResource(R.raw.mra_pub_key);  // Replace with your cert filename

            // Load the recipient's certificate
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);


            // Extract the recipient's public key from the certificate
            PublicKey publicKey = certificate.getPublicKey();
            byte[] encoded = publicKey.getEncoded();

            byte[] b64key = android.util.Base64.encode(encoded, android.util.Base64.DEFAULT);

            String b64keyString = new String(b64key, StandardCharsets.UTF_8).replace("\n", "");


            String encryptedPayload = encryptData(payload,b64keyString);

            textViewResult.setText("Encrypted Payload:\n" + encryptedPayload);
            // Execute the background task to send the payload
            new SendPayloadTask().execute(encryptedPayload);

        } catch (Exception e) {
            e.printStackTrace();
            textViewResult.setText("Encryption Failed");
            Log.e(TAG, "Encryption Failed", e);
        }
    }

    private String encryptData(String plainText, String b64PublicKey) throws Exception {
        // Convert the base64-encoded public key back to bytes
        byte[] publicKeyBytes = android.util.Base64.decode(b64PublicKey, android.util.Base64.DEFAULT);

        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

        // Initialize the Cipher with the recipient's public key for encryption using RSA/ECB/PKCS1Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Encrypt the data
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        return android.util.Base64.encodeToString(encryptedBytes, android.util.Base64.NO_WRAP);
    }


}