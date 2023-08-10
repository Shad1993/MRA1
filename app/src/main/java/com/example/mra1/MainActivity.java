package com.example.mra1;

import android.content.res.Resources;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import android.os.AsyncTask;
import android.widget.Toast;

import org.json.JSONArray;
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
import javax.crypto.spec.SecretKeySpec;

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
                    String responseBody = response.body().string();
                    String jsondetails = "[\n" +
                            "  {\n" +
                            "    \"invoiceCounter\": \"1\",\n" +
                            "    \"transactionType\": \"B2C\",\n" +
                            "    \"personType\": \"VATR\",\n" +
                            "    \"invoiceTypeDesc\": \"DRN\",\n" +
                            "    \"currency\": \"MUR\",\n" +
                            "    \"invoiceIdentifier\": \"test2\",\n" +
                            "    \"invoiceRefIdentifier\": \"test1\",\n" +
                            "    \"previousNoteHash\": \"prevNote\",\n" +
                            "    \"reasonStated\": \"return of product\",\n" +
                            "    \"totalVatAmount\": \"3400\",\n" +
                            "    \"totalAmtWoVatCur\": \"310.0\",\n" +
                            "    \"totalAmtWoVatMur\": \"10\",\n" +
                            "    \"totalAmtPaid\": \"6400\",\n" +
                            "    \"dateTimeInvoiceIssued\": \"20230810 15:27:42\",\n" +
                            "    \"seller\": {\n" +
                            "      \"name\": \"Testing LTD\",\n" +
                            "      \"tan\": \"20385979\",\n" +
                            "      \"brn\": \"C07073938\",\n" +
                            "      \"businessAddr\": \"Test address\",\n" +
                            "      \"businessPhoneNum\": \"2076000\",\n" +
                            "      \"ebsCounterNo\": \"a1\"\n" +
                            "    },\n" +
                            "    \"buyer\": {\n" +
                            "      \"name\": \"James\",\n" +
                            "      \"tan\": \"12345678\",\n" +
                            "      \"brn\": \"\",\n" +
                            "      \"businessAdd\": \"\",\n" +
                            "      \"buyerType\": \"VATR\",\n" +
                            "      \"nic\": \"\"\n" +
                            "    },\n" +
                            "    \"itemList\": [\n" +
                            "      {\n" +
                            "        \"itemNo\": \"1\",\n" +
                            "        \"taxCode\": \"TC01\",\n" +
                            "        \"nature\": \"GOODS\",\n" +
                            "        \"currency\": \"MUR\",\n" +
                            "        \"itemCode\": \"1\",\n" +
                            "        \"itemDesc\": \"2\",\n" +
                            "        \"quantity\": \"3\",\n" +
                            "        \"unitPrice\": \"20\",\n" +
                            "        \"discount\": \"0\",\n" +
                            "        \"amtWoVatCur\": \"60\",\n" +
                            "        \"amtWoVat\": \"50\",\n" +
                            "        \"tds\": \"5\",\n" +
                            "        \"vatAmt\": \"10\",\n" +
                            "        \"totalPrice\": \"60\"\n" +
                            "      }\n" +
                            "    ],\n" +
                            "    \"salesTransactions\": \"CASH\",\n" +
                            "    \"paymentMethods\": \"CASH\"\n" +
                            "  }\n" +
                            "]";

                    // Parse the response JSON to extract the key
                    JSONObject responseJson = new JSONObject(responseBody);
                    String encryptedKeyBase64  = responseJson.getString("key");
                    String encryptedtokenBase64  = responseJson.getString("token");

                    // Decrypt the encrypted key using the key from your payload
                    String decryptedKey = decryptKey(encryptedKeyBase64, "dGbv+remn7/J7bdO2OKCbg==");

                    // Now you have the decrypted key to use for encryption
                    String encryptedInvoice = encryptedInvoice(jsondetails, decryptedKey);


                    // Construct the JSON request body
                    JSONObject requestBodyMRAQR = new JSONObject();
                    requestBodyMRAQR.put("requestId", "20230324213055"); // Replace with your request ID
                    requestBodyMRAQR.put("requestDateTime", "20230810 15:27:42");
                    requestBodyMRAQR.put("signedHash", ""); // Replace with your request ID
                    requestBodyMRAQR.put("encryptedInvoice",encryptedInvoice);

                    OkHttpClient clients = new OkHttpClient();

                    MediaType mediaTypes = MediaType.parse("application/json");
                    RequestBody body1 = RequestBody.create(mediaTypes, requestBodyMRAQR.toString());

                    Request requests = new Request.Builder()
                            .url("https://vfisc.mra.mu/realtime/invoice/transmit")
                            .addHeader("Content-Type", "application/json")

                            .addHeader("token", encryptedtokenBase64)
                            .addHeader("ebsMraId", "16887088519063EJ7S0ZS109")
                            .addHeader("username", "LBatour")
                            .addHeader("areaCode", "734")
                            .post(body1)
                            .build();

                    Response responsesQRMRA = clients.newCall(requests).execute();
                    if (responsesQRMRA.isSuccessful()) {
                        String responseBody1 = responsesQRMRA.body().string();
                        JSONObject responseJsonqr = new JSONObject(responseBody1);
                        Log.d("code", responseBody1); // Log the QR code string
                        String qr = responseJsonqr.getJSONObject("fiscalisedInvoices").getString("qrCode");
                        Log.d("qr", responseBody1); // Log the QR code string


// If QR code not found, return appropriate message
                        return qr;
                    } else {
                        return "Error response code: " + responsesQRMRA.code();
                    }

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
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    textViewResult.setText("QR Code:\n" + result);
                    Log.d("qrcode", result); // Log the QR code string
                }
            });
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
                    " \"encryptKey\": \"dGbv+remn7/J7bdO2OKCbg==\",\n" +
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


    private String decryptKey(String encryptedKeyBase64, String encryptionKeyFromPayload) throws Exception {
        byte[] encryptedKeyBytes = Base64.decode(encryptedKeyBase64, Base64.DEFAULT);
        byte[] encryptionKeyBytes = Base64.decode(encryptionKeyFromPayload, Base64.DEFAULT);

        SecretKeySpec secretKeySpec = new SecretKeySpec(encryptionKeyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedKeyBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }


    private String encryptedInvoice(String plainText, String encryptionKey) throws Exception {
        byte[] keyBytes = Base64.decode(encryptionKey, Base64.DEFAULT);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        return Base64.encodeToString(encryptedBytes, Base64.NO_WRAP);
    }

}