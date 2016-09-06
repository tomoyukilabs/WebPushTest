package jp.othersight;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
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
import java.security.Signature;
import java.security.SignatureException;
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
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.json.JSONArray;
import org.json.JSONObject;

public class WebPush {
  private static final String keyAlgorithm = "ECDH";
  private static final String keyAlgorithmProvider = "BC";
  private static final String signAlgorithm = "SHA256withECDSA";
  private static final String keyCurve = "prime256v1";
  private static final String encryptionAlgorithm = "AES";
  private static final String curveName = "P-256";
  private static final String hashAlgorithm = "hmacSHA256";
  private static final String blockEncryptionAlgorithm ="AES/GCM/NoPadding";
  private static final String encoding00 = "aesgcm128";
  private static final String encoding01 = "aesgcm";
  private static final String infoAuth = "Content-Encoding: auth";
  private static final String infoCEK00 = "Content-Encoding: " + encoding00; // draft-ietf-httpbis-encryption-encoding-00
  private static final String infoCEK01 = "Content-Encoding: " + encoding01; // draft-ietf-httpbis-encryption-encoding-01
  private static final String infoNonce = "Content-Encoding: nonce";
  private static final int authLength = 32;
  private static final int tagLength = 16;
  private static final int keyLength = 16;
  private static final int nonceLength = 12;
  private static final int recordSize = 4096;

  public static final String GCM_URL = "https://android.googleapis.com/gcm/send";
  public static final String GCM_WEBPUSH_ENDPOINT = "https://gcm-http.googleapis.com/gcm";

  private static String mGcmServerKey = "";
  private static ECPrivateKey mPrivateKey = null;
  private static ECPublicKey mPublicKey = null;

  public static void setGcmServerKey(String key) {
    mGcmServerKey = key;
  }

  public static ECPrivateKey getPrivateKey() {
    return mPrivateKey;
  }

  public static ECPublicKey getPublicKey() {
    return mPublicKey;
  }

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

  public static KeyPair generateKeyPairForECDSA(String type) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    KeyPair keyPair = generateKeyPair(type);
    mPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    mPublicKey = (ECPublicKey) keyPair.getPublic();
    return keyPair;
  }

  public static KeyPair generateKeyPair(String type) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    ECParameterSpec param = ECNamedCurveTable.getParameterSpec(keyCurve);
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(type, keyAlgorithmProvider);
    keyGen.initialize(param);
    return keyGen.generateKeyPair();
  }

  public static ECPublicKey importPublicKeyForECDSA(String type, String x, String y) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    mPublicKey = importPublicKey(type, x, y);
    return mPublicKey;
  }

  public static ECPublicKey importPublicKey(String type, String x, String y) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    ECParameterSpec param = ECNamedCurveTable.getParameterSpec(keyCurve);
    ECPublicKeySpec keySpec = new ECPublicKeySpec(
        param.getCurve().validatePoint(
            new BigInteger(1, Base64.getUrlDecoder().decode(x)),
            new BigInteger(1, Base64.getUrlDecoder().decode(y))),
        param);
    KeyFactory keyFactory = KeyFactory.getInstance(type, keyAlgorithmProvider);
    return (ECPublicKey) keyFactory.generatePublic(keySpec);
  }

  public static ECPublicKey importPublicKeyForECDSA(String type, String q) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    mPublicKey = importPublicKey(type, q);
    return mPublicKey;
  }

  public static ECPublicKey importPublicKey(String type, String q) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    ECParameterSpec param = ECNamedCurveTable.getParameterSpec(keyCurve);
    ECPublicKeySpec keySpec = new ECPublicKeySpec(
        param.getCurve().decodePoint(Base64.getUrlDecoder().decode(q)),
        param);
    KeyFactory keyFactory = KeyFactory.getInstance(type, keyAlgorithmProvider);
    return (ECPublicKey) keyFactory.generatePublic(keySpec);
  }

  public static ECPrivateKey importPrivateKeyForECDSA(String type, String d) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    mPrivateKey = importPrivateKey(type, d);
    return mPrivateKey;
  }

  public static ECPrivateKey importPrivateKey(String type, String d) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    ECParameterSpec param = ECNamedCurveTable.getParameterSpec(keyCurve);
    ECPrivateKeySpec keySpec = new ECPrivateKeySpec(
        new BigInteger(1, (Base64.getUrlDecoder().decode(d))),
        param);
    KeyFactory keyFactory = KeyFactory.getInstance(type, keyAlgorithmProvider);
    return (ECPrivateKey) keyFactory.generatePrivate(keySpec);
  }

  public static void sendWebPush(String key, String auth, String endpoint, String payload, int version) {
    sendWebPush(key, auth, endpoint, payload, version, null);
  }

  private static SecretKey generateSharedKey(ECPublicKey publicKey, ECPrivateKey privateKey) {
    try {
      KeyAgreement keyAgree = KeyAgreement.getInstance(keyAlgorithm, keyAlgorithmProvider);
      keyAgree.init(privateKey);
      keyAgree.doPhase(publicKey, true);
      return keyAgree.generateSecret(encryptionAlgorithm);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
      e.printStackTrace();
      return null;
    }
  }

  // conforms to draft-ietf-httpbis-encryption-encoding-(version)
  public static JSONObject sendWebPush(String key, String auth, String endpoint, String payload, int version, JSONObject info) {
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
      return new JSONObject().put("error", "cannot initialize SecureRandom");
    }

    byte[] salt = new byte[16];
    random.nextBytes(salt);

    if((key != null) && (payload != null)) {
      // create a shared secret key for AES encryption
      
      try {
        // local key pair
        KeyPair localKeys = generateKeyPair(keyAlgorithm);
        localPublicKey = (ECPublicKey)localKeys.getPublic();

        // user public key
        userPublicKey = importPublicKey(keyAlgorithm, key);

        // key agreement
        secretKey = generateSharedKey(userPublicKey, (ECPrivateKey) localKeys.getPrivate());
      } catch (NoSuchAlgorithmException
          | NoSuchProviderException
          | InvalidAlgorithmParameterException
          | InvalidKeySpecException e) {
        e.printStackTrace();
      }

      if(secretKey != null) {
        // generate an encryption key using HMAC-based Key Derivation Function (HKDF)
        byte[] prk = null;
        byte[] ikm = null;
        ByteBuffer context = null;
        if(auth != null) {
          byte[] tmpPrk = extractHKDF(Base64.getUrlDecoder().decode(auth), secretKey.getEncoded());
          ByteBuffer bufferAuth = ByteBuffer.allocate(infoAuth.length() + 1).put(infoAuth.getBytes()).put((byte)0x00);
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

            // encryption with padding
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
    // post the push message (with the encrypted payload, if any)
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
            "keyid=p256dh;dh=" + Base64.getUrlEncoder().encodeToString(localPublicKey.getQ().getEncoded(false)).replaceAll("=+$", ""));
        conn.setRequestProperty("Encryption",
            "keyid=p256dh;salt=" + Base64.getUrlEncoder().encodeToString(salt).replaceAll("=+$", ""));
        conn.setRequestProperty("Content-Encoding", (version == 1) ? encoding01 : encoding00);
      }
      conn.setRequestProperty("TTL",  String.format("%d",  2*24*60*60)); // 2 days in second

      if(endpoint.startsWith(GCM_WEBPUSH_ENDPOINT) || endpoint.startsWith(GCM_URL))
        conn.setRequestProperty("Authorization",  "key=" + mGcmServerKey);

      if(info != null) {
        // JWT Header
        JSONObject h = new JSONObject();
        h.put("typ", "JWT");
        h.put("alg", "ES256");
        // JWT Payload
        JSONObject p = new JSONObject();
        String aud = info.optString("aud");
        String sub = info.optString("sub");
        if(aud != null)
          p.put("aud", aud);
        if(sub != null)
          p.put("sub", sub);
        long cur = System.currentTimeMillis() / 1000;
        p.put("exp", cur + 12*60*60); // 12 hours
        // p.put("iat", cur);
        String claim = Base64.getUrlEncoder().encodeToString(h.toString().getBytes()).replaceAll("=+$", "")
            + "." + Base64.getUrlEncoder().encodeToString(p.toString().getBytes()).replaceAll("=+$", "");

        // VAPID: create a signature by SHA-256 with ECDSA
        try {
          Signature signer = Signature.getInstance(signAlgorithm, keyAlgorithmProvider);
          signer.initSign(mPrivateKey);
          signer.update(claim.getBytes());

          // convert ASN.1 to JWS (i.e. concatenated R and S raw bytes)
          int pos;
          ByteBuffer asn1 = ByteBuffer.wrap(signer.sign());
          ByteBuffer signature = ByteBuffer.allocate(64);

          asn1.position(3);
          int l1 = (int) asn1.get();

          pos = 4 + l1 - 32;
          asn1.limit(pos + 32);
          asn1.position(pos);
          signature.put(asn1);
          pos += 33;
          asn1.limit(asn1.capacity());
          asn1.position(pos);
          int l2 = (int) asn1.get();
          pos += 1 + l2 - 32;
          asn1.limit(pos + 32);
          asn1.position(pos);
          signature.put(asn1);

          conn.setRequestProperty(
              "Crypto-Key",
              conn.getRequestProperty("Crypto-Key") + ";p256ecdsa="
              + Base64.getUrlEncoder().encodeToString(mPublicKey.getQ().getEncoded(false)).replaceAll("=+$", ""));
          conn.setRequestProperty(
              "Authorization",
              "WebPush " + claim + "." + Base64.getUrlEncoder().encodeToString(signature.array()).replaceAll("=+$", ""));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
          e.printStackTrace();
        }
      }

      BufferedOutputStream out = new BufferedOutputStream(conn.getOutputStream());
      if(encrypted)
        out.write(output.array());
      else {
        out.write(new byte[0]);
      }
      out.flush();
      out.close();
      int status = conn.getResponseCode();
      StringBuffer response = new StringBuffer();
      JSONObject result = new JSONObject().put("status", status);
      if(status < HttpURLConnection.HTTP_BAD_REQUEST) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        String buf;
        while((buf = reader.readLine()) != null) {
          response.append(buf);
        }
        reader.close();
        System.out.println("======= Web Push Sent =======");
        System.out.println(response.toString());
      }
      else {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "UTF-8"));
        String buf;
        while((buf = reader.readLine()) != null) {
          response.append(buf);
        }
        reader.close();
        System.out.println("======= Web Push Failed =======");
        System.out.println(response.toString());
      }
      conn.disconnect();
      result.put("response", response.toString());
      return result;
    } catch (MalformedURLException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
      if(conn != null)
        conn.disconnect();
    }
    return new JSONObject().put("error", "internal server error");
  }

  public static JSONObject sendPushViaGoogleCloudMessaging(String registrationID) {
    HttpURLConnection conn = null;
    URL url;

    try {
      url = new URL(GCM_URL);
      conn = (HttpURLConnection)url.openConnection();
      conn.setRequestMethod("POST");
      conn.setDoOutput(true);
      conn.setRequestProperty("Authorization",  "key=" + mGcmServerKey);
      conn.setRequestProperty("Content-Type", "application/json");
      BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));
      JSONObject json = new JSONObject().put("registration_ids", new JSONArray().put(registrationID));
      writer.write(json.toString());
      writer.flush();
      writer.close();
      int status = conn.getResponseCode();
      StringBuffer response = new StringBuffer();
      JSONObject result = new JSONObject().put("status", status);
      if(status < HttpURLConnection.HTTP_BAD_REQUEST) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        String buf;
        while((buf = reader.readLine()) != null) {
          response.append(buf);
        }
        reader.close();
        System.out.println("======= GCM Push Sent =======");
        System.out.println(response.toString());
      }
      else {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "UTF-8"));
        String buf;
        while((buf = reader.readLine()) != null) {
          response.append(buf);
        }
        reader.close();
        System.out.println("======= GCM Push Failed =======");
        System.out.println(response.toString());
      }
      conn.disconnect();
      result.put("response", response.toString());
      return result;
    } catch (MalformedURLException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
      if(conn != null)
        conn.disconnect();
    }
    return new JSONObject().put("error", "internal server error");
  }
}