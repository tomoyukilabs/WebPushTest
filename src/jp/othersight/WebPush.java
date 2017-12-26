package jp.othersight;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
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
  private static final String encoding_aes128gcm = "aes128gcm";
  private static final String encoding_aesgcm = "aesgcm";
  private static final String encoding_aesgcm128 = "aesgcm128";
  private static final String infoAuth_aes128gcm = "WebPush: info";
  private static final String infoAuth_aesgcm = "Content-Encoding: auth";
  private static final String infoCEK_aes128gcm = "Content-Encoding: " + encoding_aes128gcm; // draft-ietf-httpbis-encryption-encoding-09
  private static final String infoCEK_aesgcm = "Content-Encoding: " + encoding_aesgcm; // draft-ietf-httpbis-encryption-encoding-01
  private static final String infoCEK_aesgcm128 = "Content-Encoding: " + encoding_aesgcm128; // draft-ietf-httpbis-encryption-encoding-00
  private static final String infoNonce = "Content-Encoding: nonce";
  private static final int authLength = 32;
  private static final int tagLength = 16;
  private static final int keyLength = 16;
  private static final int nonceLength = 12;
  private static final int recordSize = 4096;

  public static final String GCM_URL = "https://android.googleapis.com/gcm/send";
  public static final String GCM_WEBPUSH_ENDPOINT = "https://gcm-http.googleapis.com/gcm";

  public static final int VAPID_DRAFT_IETF_WEBPUSH_VAPID_01 = 0;
  public static final int VAPID_RFC8292 = 1;

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

  private static byte[] extractHKDF(byte[] salt, byte[] key) throws GeneralSecurityException {
    Mac mac = Mac.getInstance(hashAlgorithm);
    SecretKeySpec spec = new SecretKeySpec(salt, hashAlgorithm);
    mac.init(spec);
    return mac.doFinal(key);
  }

  private static byte[] expandHKDF(byte[] prk, ByteBuffer info, int length) throws GeneralSecurityException {
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

  private static byte[] generateSalt() {
    SecureRandom random;
    try {
      random = SecureRandom.getInstance("NativePRNGNonBlocking");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      return null;
    }

    byte[] salt = new byte[16];
    random.nextBytes(salt);
    return salt;
  }

  private static byte[] generateCEK(String info, byte[] prk) throws GeneralSecurityException {
    return generateCEK(info, prk, ByteBuffer.allocate(0));
  }

  private static byte[] generateCEK(String info, byte[] prk, ByteBuffer context) throws GeneralSecurityException {
    int contextLength = (context != null) ? (context.capacity() + 1) : 0;
    ByteBuffer cekInfo = ByteBuffer.allocate(info.length() + contextLength).put(info.getBytes());
    if(context != null) {
      cekInfo.put((byte)0);
      cekInfo.put(context);
      context.rewind();
    }
    cekInfo.rewind();
    return expandHKDF(prk, cekInfo, keyLength);
  }

  private static byte[] generateNonce(byte[] prk) throws GeneralSecurityException {
    return generateNonce(prk, ByteBuffer.allocate(0));
  }

  private static byte[] generateNonce(byte[] prk, ByteBuffer context) throws GeneralSecurityException {
    int contextLength = (context != null) ? (context.capacity() + 1) : 0;
    ByteBuffer info = ByteBuffer.allocate(infoNonce.length() + contextLength).put(infoNonce.getBytes());
    if(context != null) {
      info.put((byte)0);
      info.put(context);
      context.rewind();
    }
    info.rewind();
    return expandHKDF(prk, info, nonceLength);
  }

  private static byte[] encryptRecordWithDelimiter(byte[] k, byte[] n, ByteBuffer buf, byte delimiter, long counter) {
    byte[] nonce = generateNonce(n, counter);

    try {
      IvParameterSpec iv = new IvParameterSpec(nonce);
      Cipher cipher = Cipher.getInstance(blockEncryptionAlgorithm, keyAlgorithmProvider);
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, encryptionAlgorithm), iv);

      final int size = buf.limit() - buf.position();
      ByteBuffer input = ByteBuffer.allocate(size + 2);
      input.put(buf);
      input.put(delimiter);
      input.put((byte)0);
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

  private static byte[] encryptRecordWithPadding(byte[] k, byte[] n, ByteBuffer buf, int padding, long counter) {
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

  private static ByteBuffer encrypt(String info, byte[] prk, String payload) throws GeneralSecurityException {
    byte[] hashInfoKey = generateCEK(info, prk);
    byte[] hashInfoNonce = generateNonce(prk);
    final int overhead = tagLength + 2; // tag length (=16) + delimiter (=1) + padding (one or more bytes of 0x00)

    try {
      ByteBuffer input = ByteBuffer.wrap(payload.getBytes("UTF-8"));
      int blocks = input.capacity() / (recordSize - overhead);
      int remaining = input.capacity() - blocks * (recordSize - overhead);
      ByteBuffer output = ByteBuffer.allocate(blocks * (recordSize + overhead) + remaining + overhead);
      long counter = 0;
      boolean isLast = false;
      while(!isLast) {
        int length = recordSize - overhead;
        if(input.position() + length >= input.capacity()) {
          length = input.capacity() - input.position();
          isLast = true;
        }
        input.limit(input.position() + length);
        output.limit(output.position() + length + overhead);
        output.put(encryptRecordWithDelimiter(hashInfoKey, hashInfoNonce, input, (byte)(isLast ? 2 : 1), counter));
        input.position(input.limit());
        counter++;
      }
      output.rewind();
      return output;
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
      return null;
    }
  }

  private static ByteBuffer encrypt(String info, byte[] prk, String payload, ByteBuffer context, int padding) throws GeneralSecurityException {
    byte[] hashInfoKey = generateCEK(info, prk, context);
    byte[] hashInfoNonce = generateNonce(prk, context);
    try {
      ByteBuffer input = ByteBuffer.wrap(payload.getBytes("UTF-8"));
      int blocks = input.capacity() / (recordSize - padding);
      int remaining = input.capacity() - blocks * (recordSize - padding);
      ByteBuffer output = ByteBuffer.allocate(blocks * (recordSize + tagLength) + ((remaining == 0) ? 0 : (remaining + tagLength + padding)));
      long counter = 0;
      while(input.position() < input.capacity()) {
        int length = recordSize - padding;
        if(input.position() + length > input.capacity())
          length = input.capacity() - input.position();
        input.limit(input.position() + length);
        output.limit(output.position() + length + tagLength + padding);
        output.put(encryptRecordWithPadding(hashInfoKey, hashInfoNonce, input, padding, counter));
        input.position(input.limit());
        counter++;
      }
      output.rewind();
      return output;
    } catch (UnsupportedEncodingException e) {
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

  public static void sendWebPush(String key, String auth, String endpoint, String payload, String contentEncoding, int vapidVersion) {
    sendWebPush(key, auth, endpoint, payload, contentEncoding, null, vapidVersion);
  }

  private static SecretKey generateSharedKey(ECPublicKey publicKey, ECPrivateKey privateKey) throws GeneralSecurityException {
    KeyAgreement keyAgree = KeyAgreement.getInstance(keyAlgorithm, keyAlgorithmProvider);
    keyAgree.init(privateKey);
    keyAgree.doPhase(publicKey, true);
    return keyAgree.generateSecret(encryptionAlgorithm);
  }

  private static String generateJWT(JSONObject info) {
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

      return claim + "." + Base64.getUrlEncoder().encodeToString(signature.array()).replaceAll("=+$", "");
    } catch (GeneralSecurityException e) {
      e.printStackTrace();
      return null;
    }
  }

  private static class Keys {
    private SecretKey secretKey = null;
    private ECPublicKey localPublicKey = null;
    private ECPublicKey userPublicKey = null;

    Keys(String key) throws GeneralSecurityException {
      // local key pair
      KeyPair localKeys = generateKeyPair(keyAlgorithm);
      localPublicKey = (ECPublicKey)localKeys.getPublic();

      // user public key
      userPublicKey = importPublicKey(keyAlgorithm, key);

      // key agreement
      secretKey = generateSharedKey(userPublicKey, (ECPrivateKey) localKeys.getPrivate());
    }

    public SecretKey getSecretKey() { return secretKey; };
    public ECPublicKey getLocalPublicKey() { return localPublicKey; };
    public ECPublicKey getUserPublicKey() { return userPublicKey; };
  }

  public static JSONObject sendWebPush(String key, String auth, String endpoint, String payload, String contentEncoding, JSONObject info, int vapidVersion) {
    return "aes128gcm".equals(contentEncoding) ?
        sendAes128GcmWebPush(key, auth, endpoint, payload, contentEncoding, info, vapidVersion) :
        sendLegacyWebPush(key, auth, endpoint, payload, contentEncoding, info);
  }

  // "aes128gcm" content encoding
  public static JSONObject sendAes128GcmWebPush(String key, String auth, String endpoint, String payload, String contentEncoding, JSONObject info, int vapidVersion) {
    ByteBuffer header = ByteBuffer.allocate(16 + 4 + 1 + 65);
    ByteBuffer output = null;
    Keys keys = null;
    final int rs = 4096;

    if(key == null)
      return new JSONObject().put("error", "user public key is not specified");

    // the maximum payload length supported by push services is 3992 bytes
    // (= 4096 - 86 (header) - 2 (padding) - 16 (expansion of AEAD_AES_128_GCM))
    if(payload.length() > 3992)
      return new JSONObject().put("error", "payload is too long (> 3992 bytes)");

    byte[] salt = generateSalt();
    if(salt == null)
      return new JSONObject().put("error", "cannot initialize SecureRandom");

    // create a shared secret key for AES encryption
    try {
      keys = new Keys(key);
    } catch (GeneralSecurityException e) {
      e.printStackTrace();
      return new JSONObject().put("error", "failed to initialize keys");
    }

    // Encryption Content Coding Header
    // Note: In "aes128gcm" encoding, keyid must be the ECDH public key of
    // the application server (draft-ietf-webpush-encryption-08)
    header.put(salt);
    header.putInt(rs);
    header.put((byte)65);
    header.put(keys.getLocalPublicKey().getQ().getEncoded(false));
    header.rewind();

    // generate CEK and nonce, and encrypt the given payload
    if(auth == null) {
      return new JSONObject().put("error", "auth parameter from UA is not speficied");
    }
    try {
      byte[] prkKey = extractHKDF(Base64.getUrlDecoder().decode(auth), keys.getSecretKey().getEncoded());
      ByteBuffer keyInfo = ByteBuffer.allocate(infoAuth_aes128gcm.length() + 1 + 65 + 65)
          .put(infoAuth_aes128gcm.getBytes())
          .put((byte)0)
          .put(keys.getUserPublicKey().getQ().getEncoded(false))
          .put(keys.getLocalPublicKey().getQ().getEncoded(false));
      keyInfo.rewind();
      byte[] ikm = expandHKDF(prkKey, keyInfo, authLength);
      byte[] prk = extractHKDF(salt, ikm);
      output = encrypt(infoCEK_aes128gcm, prk, payload != null ? payload : "");
    } catch (GeneralSecurityException e) {
      e.printStackTrace();
      return new JSONObject().put("error", "failed to generate content encryption key");
    }

    // post the push message (with the encrypted payload, if any)
    HttpURLConnection conn = null;
    URL url;
    try {
      url = new URL(endpoint);
      conn = (HttpURLConnection)url.openConnection();
      conn.setRequestMethod("POST");
      conn.setDoOutput(true);

      conn.setRequestProperty("Content-Length", String.format("%d", header.capacity() + output.capacity()));
      conn.setRequestProperty("Content-Encoding", encoding_aes128gcm);
      conn.setRequestProperty("TTL",  String.format("%d",  2*24*60*60)); // 2 days in second

      if(info != null) {
        // VAPID: create a signature by SHA-256 with ECDSA
        String jwt = generateJWT(info);

        switch (vapidVersion) {
        // draft-ietf-webpush-vapid-01
        case VAPID_RFC8292:
          // VAPID: create a signature by SHA-256 with ECDSA (RFC 8292)
          conn.setRequestProperty(
              "Authorization",
              "vapid t=" + jwt + ", k=" + Base64.getUrlEncoder().encodeToString(mPublicKey.getQ().getEncoded(false)).replaceAll("=+$", ""));
          break;
        case VAPID_DRAFT_IETF_WEBPUSH_VAPID_01:
          conn.setRequestProperty(
              "Crypto-Key",
              "p256ecdsa=" + Base64.getUrlEncoder().encodeToString(mPublicKey.getQ().getEncoded(false)).replaceAll("=+$", ""));
          conn.setRequestProperty("Authorization", "WebPush " + jwt);
          break;
        }
      }

      BufferedOutputStream out = new BufferedOutputStream(conn.getOutputStream());
      out.write(header.array());
      out.write(output.array());
      out.flush();
      out.close();

      int status = conn.getResponseCode();
      StringBuffer response = new StringBuffer();
      JSONObject result = new JSONObject().put("status", status);

      try {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        String buf;
        while((buf = reader.readLine()) != null) {
          response.append(buf);
        }
        reader.close();
        System.out.println("======= Web Push Sent =======");
        System.out.println(response.toString());
      }
      catch(IOException e) {
        InputStream in = conn.getErrorStream();
        if(in != null) {
          BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
          String buf;
          while((buf = reader.readLine()) != null) {
            response.append(buf);
          }
          reader.close();
        }
        else {
          response.append("HTTP response error code: " + status);
        }
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

  // "aesgcm" and "aesgcm128" content encoding
  public static JSONObject sendLegacyWebPush(String key, String auth, String endpoint, String payload, String contentEncoding, JSONObject info) {
    ByteBuffer output = null;
    Keys keys = null;
    final boolean isAesgcm = encoding_aesgcm.equals(contentEncoding);

    byte[] salt = generateSalt();
    if(salt == null)
      return new JSONObject().put("error", "cannot initialize SecureRandom");

    if((key != null) && (payload != null)) {
      // create a shared secret key for AES encryption
      
      try {
        keys = new Keys(key);
      } catch (GeneralSecurityException e) {
        e.printStackTrace();
        return new JSONObject().put("error", "failed to initialize keys");
      }

      // generate IKM
      byte[] prk = null;
      byte[] ikm = null;
      ByteBuffer context = null;
      if(auth != null) {
        try {
          byte[] prkKey = extractHKDF(Base64.getUrlDecoder().decode(auth), keys.getSecretKey().getEncoded());
          ByteBuffer keyInfo = ByteBuffer.allocate(infoAuth_aesgcm.length() + 1).put(infoAuth_aesgcm.getBytes()).put((byte)0);
          keyInfo.rewind();
          ikm = expandHKDF(prkKey, keyInfo, authLength);
          byte[] recipient = keys.getUserPublicKey().getQ().getEncoded(false);
          byte[] sender = keys.getLocalPublicKey().getQ().getEncoded(false);
          context = ByteBuffer.allocate(curveName.length() + recipient.length + sender.length + 5);
          context.put(curveName.getBytes()).put((byte)0)
            .putShort((short)recipient.length).put(recipient)
            .putShort((short)sender.length).put(sender);
          context.rewind();
        } catch (GeneralSecurityException e) {
          e.printStackTrace();
          return new JSONObject().put("error", "failed to generate context");
        }
      }
      else {
        ikm = keys.getSecretKey().getEncoded();
      }
      try {
        prk = extractHKDF(salt, ikm);
      } catch (GeneralSecurityException e) {
        e.printStackTrace();
        return new JSONObject().put("error", "failed to generate PRK");
      }

      // encryption with padding
      try {
        output = encrypt(isAesgcm ? infoCEK_aesgcm : infoCEK_aesgcm128, prk, payload, context, isAesgcm ? 2 : 1);
      } catch (GeneralSecurityException e) {
        e.printStackTrace();
        return new JSONObject().put("error", "failed to generate CEK or nonce");
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
      if(keys != null) {
        conn.setRequestProperty("Content-Type", "application/octet-stream");
        conn.setRequestProperty("Content-Length", String.format("%d", output.capacity()));
        conn.setRequestProperty((auth != null) ? "Crypto-Key" : "Encryption-Key",
            "dh=" + Base64.getUrlEncoder().encodeToString(keys.getLocalPublicKey().getQ().getEncoded(false)).replaceAll("=+$", ""));
        conn.setRequestProperty("Encryption",
            "salt=" + Base64.getUrlEncoder().encodeToString(salt).replaceAll("=+$", ""));
        conn.setRequestProperty("Content-Encoding", contentEncoding);
      }
      conn.setRequestProperty("TTL",  String.format("%d",  2*24*60*60)); // 2 days in second

      if(endpoint.startsWith(GCM_WEBPUSH_ENDPOINT) || endpoint.startsWith(GCM_URL))
        conn.setRequestProperty("Authorization",  "key=" + mGcmServerKey);

      if(info != null) {
        // VAPID: create a signature by SHA-256 with ECDSA (draft-ietf-webpush-vapid-01)
        String jwt = generateJWT(info);
        conn.setRequestProperty(
            "Crypto-Key",
            conn.getRequestProperty("Crypto-Key") + ";p256ecdsa="
            + Base64.getUrlEncoder().encodeToString(mPublicKey.getQ().getEncoded(false)).replaceAll("=+$", ""));
        conn.setRequestProperty("Authorization", "WebPush " + jwt);
      }

      BufferedOutputStream out = new BufferedOutputStream(conn.getOutputStream());
      if(keys != null)
        out.write(output.array());
      else {
        out.write(new byte[0]);
      }
      out.flush();
      out.close();
      int status = conn.getResponseCode();
      StringBuffer response = new StringBuffer();
      JSONObject result = new JSONObject().put("status", status);
      try {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        String buf;
        while((buf = reader.readLine()) != null) {
          response.append(buf);
        }
        reader.close();
        System.out.println("======= Web Push Sent =======");
        System.out.println(response.toString());
      }
      catch(IOException e) {
        InputStream in = conn.getErrorStream();
        if(in != null) {
          BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
          String buf;
          while((buf = reader.readLine()) != null) {
            response.append(buf);
          }
          reader.close();
        }
        else
          response.append("HTTP response error code: " + status);
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