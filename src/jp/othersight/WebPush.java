package jp.othersight;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import org.json.JSONArray;
import org.json.JSONObject;

public class WebPush {
  private static final String keyAlgorithm = "ECDH";
  private static final String keyAlgorithmProvider = "BC";
  private static final String encryptionAlgorithm = "AES";
  private static final String curveName = "P-256";
  private static final String hashAlgorithm = "hmacSHA256";
  private static final String blockEncryptionAlgorithm ="AES/GCM/NoPadding";
  private static final String encoding00 = "aesgcm128";
  private static final String encoding01 = "aesgcm";
  private static final String infoAuth = "Content-Encoding: auth";
  private static final String infoCEK00 = "Content-Encoding: " + encoding00; // draft-ietf-httpbis-encryption-encoding-00
  private static final String infoCEK01 = "Content-Encoding: " + encoding01; // draft on GitHub (IETF HTTP WG)
  private static final String infoNonce = "Content-Encoding: nonce";
  private static final int authLength = 32;
  private static final int tagLength = 16;
  private static final int keyLength = 16;
  private static final int nonceLength = 12;
  private static final int recordSize = 4096;

  public static final String GCM_URL = "https://android.googleapis.com/gcm/send";
  public static final String GCM_WEBPUSH_ENDPOINT = "https://jmt17.google.com/gcm/demo-webpush-00";
  public static final String GCM_SERVER_KEY = ""; // set your Google Cloud Messaging API key

  private static byte[] extractHKDF(byte[] salt, byte[] key) {
    try {
      Mac mac = Mac.getInstance(hashAlgorithm);
      SecretKeySpec spec = new SecretKeySpec(salt, hashAlgorithm);
      mac.init(spec);
      return mac.doFinal(key);
    } catch (NoSuchAlgorithmException
        | InvalidKeyException e) {
      e.printStackTrace();
      return null;
    }
  }

  private static byte[] expandHKDF(byte[] prk, ByteBuffer info, int length) {
    try {
      Mac mac = Mac.getInstance(hashAlgorithm);
      SecretKeySpec spec = new SecretKeySpec(prk, hashAlgorithm);
      mac.init(spec);
      ByteBuffer input = ByteBuffer.allocate(info.capacity() + 1);
      input.put(info);
      info.rewind();
      input.put((byte)1);
      input.rewind();
      ByteBuffer result = ByteBuffer.allocate(length);
      result.put(mac.doFinal(input.array()), 0, length);
      return result.array();
    } catch (NoSuchAlgorithmException
        | InvalidKeyException e) {
      e.printStackTrace();
      return null;
    }
  }

  private static byte[] generateNonce(byte[] base, long c) {
    ByteBuffer buf = ByteBuffer.wrap(base);
    ByteBuffer counter = ByteBuffer.allocate(8);
    counter.putLong(c);
    counter.position(2);
    for(int i = base.length - 6 ; i < base.length ; i++) {
      byte b = (byte)(buf.get(i) ^ counter.get());
      buf.position(i);
      buf.put(b);
    }
    return buf.array();
  }

  private static byte[] encryptRecord(byte[] k, byte[] n, ByteBuffer buf, int padding, long counter) {
    byte[] nonce = generateNonce(n, counter);

    try {
      IvParameterSpec iv = new IvParameterSpec(nonce);
      Cipher cipher = Cipher.getInstance(blockEncryptionAlgorithm, keyAlgorithmProvider);
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, encryptionAlgorithm), iv);

      ByteBuffer input = ByteBuffer.allocate(buf.limit() - buf.position() + padding);
      for(int i = 0 ; i < padding ; i++)
        input.put((byte)0);
      input.put(buf);
      byte[] buffer = new byte[cipher.getOutputSize(input.capacity())];
      int l = cipher.update(input.array(), 0, input.capacity(), buffer);
      byte[] remaining = cipher.doFinal();
      ByteBuffer result = ByteBuffer.allocate(buffer.length);
      result.put(buffer, 0, l);
      result.put(remaining);
      return result.array();
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | NoSuchPaddingException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | IllegalBlockSizeException
        | BadPaddingException
        | ShortBufferException e) {
      e.printStackTrace();
      return null;
    }
  }

  // conforms to draft-ietf-httpbis-encryption-encoding-00, if version == 0
  // conforms to the latest version on GitHub, if version == 1
  public static void sendWebPush(String key, String auth, String endpoint, String payload, int version) {
    boolean encrypted = false;
    ByteBuffer output = null;
    SecretKey secretKey = null;
    ECPublicKey localPublicKey = null;
    ECPublicKey userPublicKey = null;

    SecureRandom random;
    try {
      random = SecureRandom.getInstance("NativePRNGNonBlocking");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      return;
    }

    byte[] salt = new byte[16];
    random.nextBytes(salt);

    if((key != null) && (payload != null) && (payload.length() > 0)) {
      // create a shared secret key for AES encryption
      
      try {
        // local key pair
        ECParameterSpec param = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm, keyAlgorithmProvider);
        keyGen.initialize(param);
        KeyPair localKeys = keyGen.generateKeyPair();
        localPublicKey = (ECPublicKey)localKeys.getPublic();

        // user public key
        ECPublicKeySpec userPublicKeySpec = new ECPublicKeySpec(
            param.getCurve().decodePoint(Base64.getUrlDecoder().decode(key)),
            param);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", keyAlgorithmProvider);
        userPublicKey = (ECPublicKey) keyFactory.generatePublic(userPublicKeySpec);

        // key agreement
        KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH", keyAlgorithmProvider);
        keyAgree.init(localKeys.getPrivate());
        keyAgree.doPhase(userPublicKey, true);
        secretKey = keyAgree.generateSecret(encryptionAlgorithm);
      } catch (NoSuchAlgorithmException
          | NoSuchProviderException
          | InvalidAlgorithmParameterException
          | InvalidKeySpecException
          | InvalidKeyException e) {
        e.printStackTrace();
      }

      if(secretKey != null) {
        // generate an encryption key using HMAC-based Key Derivation Function (HKDF)
        byte[] prk = null;
        byte[] ikm = null;
        ByteBuffer context = null;
        if(auth != null) {
          byte[] tmpPrk = extractHKDF(Base64.getUrlDecoder().decode(auth), secretKey.getEncoded());
          ByteBuffer bufferAuth = ByteBuffer.allocate(infoAuth.length() + 1).put("".getBytes()).put((byte)0x00);
          bufferAuth.rewind();
          ikm = expandHKDF(tmpPrk, bufferAuth, authLength);
          byte[] recipient = userPublicKey.getQ().getEncoded(false);
          byte[] sender = localPublicKey.getQ().getEncoded(false);
          context = ByteBuffer.allocate(curveName.length() + recipient.length + sender.length + 5);
          context.put(curveName.getBytes()).put((byte)0x00)
            .putShort((short)recipient.length).put(recipient)
            .putShort((short)sender.length).put(sender);
          context.rewind();
        }
        else {
          ikm = secretKey.getEncoded();
        }
        prk = extractHKDF(salt, ikm);

        if(prk != null) {
          try {
            // Content Encryption Key (CEK) Derivation
            int contextLength = (context != null) ? (context.capacity() + 1) : 0;
            ByteBuffer bufCEK = 
              (version == 1) ?
                ByteBuffer.allocate(infoCEK01.length() + contextLength).put(infoCEK01.getBytes())
                : ByteBuffer.allocate(infoCEK00.length() + contextLength).put(infoCEK00.getBytes());
            ByteBuffer bufNonce = ByteBuffer.allocate(infoNonce.length() + contextLength).put(infoNonce.getBytes());
            // if context is null, the following implementation will perform the previous version of web push encryption
            if(context != null) {
              bufCEK.put((byte)0x00);
              bufNonce.put((byte)0x00);
              bufCEK.put(context);
              context.rewind();
              bufNonce.put(context);
              context.rewind();
            }
            bufCEK.rewind();
            bufNonce.rewind();
            byte[] hashInfoKey = expandHKDF(prk, bufCEK, keyLength);
            byte[] hashInfoNonce = expandHKDF(prk, bufNonce, nonceLength);
            ByteBuffer input = ByteBuffer.wrap(payload.getBytes("UTF-8"));
            int padding = (version == 1) ? 2 : 1;
            int blocks = input.capacity() / (recordSize - padding);
            int remaining = input.capacity() - blocks * (recordSize - padding);
            output = ByteBuffer.allocate(blocks * (recordSize + 16) + ((remaining == 0) ? 0 : (remaining + tagLength + padding)));
            long counter = 0;
            while(input.position() < input.capacity()) {
              int length = recordSize - padding;
              if(input.position() + length > input.capacity())
                length = input.capacity() - input.position();
              input.limit(input.position() + length);
              output.limit(output.position() + length + tagLength + padding);
              output.put(encryptRecord(hashInfoKey, hashInfoNonce, input, padding, counter));
              input.position(input.limit());
              counter++;
            }
  
            encrypted = true;
          } catch (UnsupportedEncodingException e) {
          }
        }
      }
    }
    HttpURLConnection conn = null;
    URL url;
    try {
      url = new URL(endpoint);
      conn = (HttpURLConnection)url.openConnection();
      conn.setRequestMethod("POST");
      conn.setDoOutput(true);
      if(encrypted) {
        conn.setRequestProperty("Content-Type", "application/octet-stream");
        conn.setRequestProperty("Content-Length", String.format("%d", output.capacity()));
        conn.setRequestProperty((auth != null) ? "Crypto-Key" : "Encryption-Key",
            "keyid=p256dh;dh=" + Base64.getUrlEncoder().encodeToString(localPublicKey.getQ().getEncoded(false)));
        conn.setRequestProperty("Encryption",
            "keyid=p256dh;salt=" + Base64.getUrlEncoder().encodeToString(salt));
        conn.setRequestProperty("Content-Encoding", (version == 1) ? encoding01 : encoding00);
      }
      BufferedOutputStream out = new BufferedOutputStream(conn.getOutputStream());
      if(encrypted)
        out.write(output.array());
      else {
        out.write(new byte[0]);
      }
      out.flush();
      out.close();
      if(conn.getResponseCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String response = "";
        String buf;
        while((buf = reader.readLine()) != null) {
          response += buf;
        }
        reader.close();
        conn.disconnect();
        System.out.println("======= Web Push Sent =======");
        System.out.println(response);
      }
      else {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
        String response = "";
        String buf;
        while((buf = reader.readLine()) != null) {
          response += buf;
        }
        reader.close();
        conn.disconnect();
        System.out.println("======= Web Push Failed =======");
        System.out.println(response);
      }
    } catch (MalformedURLException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
      if(conn != null)
        conn.disconnect();
    }
  }

  public static void sendPushViaGoogleCloudMessaging(String registrationID) {
    HttpURLConnection conn = null;
    URL url;

    try {
      url = new URL(GCM_URL);
      conn = (HttpURLConnection)url.openConnection();
      conn.setRequestMethod("POST");
      conn.setDoOutput(true);
      conn.setRequestProperty("Authorization",  "key=" + GCM_SERVER_KEY);
      conn.setRequestProperty("Content-Type", "application/json");
      BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));
      JSONObject json = new JSONObject().put("registration_ids", new JSONArray().put(registrationID));
      writer.write(json.toString());
      writer.flush();
      writer.close();
      if(conn.getResponseCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String response = "";
        String buf;
        while((buf = reader.readLine()) != null) {
          response += buf;
        }
        reader.close();
        conn.disconnect();
        System.out.println("======= GCM Push Failed =======");
        System.out.println(response);
      }
      else {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
        String response = "";
        String buf;
        while((buf = reader.readLine()) != null) {
          response += buf;
        }
        reader.close();
        conn.disconnect();
        System.out.println("======= GCM Push Sent =======");
        System.out.println(response);
      }
    } catch (MalformedURLException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
      if(conn != null)
        conn.disconnect();
    }
  }
}