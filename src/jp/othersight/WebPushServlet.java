package jp.othersight;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONException;
import org.json.JSONObject;

@WebServlet(name="WebPushServlet", urlPatterns="/push/*")
public class WebPushServlet extends HttpServlet {
  private static final String keyAlgorithm = "ECDSA";
  public static ECPublicKey publicKey = null;
  public static ECPrivateKey privateKey = null;

  /**
   * 
   */
  private static final long serialVersionUID = 2888859180954573814L;

  public WebPushServlet() {
    Security.addProvider(new BouncyCastleProvider());
    File file = new File("serverKey.json");
    if(file.exists()) {
      try {
        StringBuffer buf = new StringBuffer();
        BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
        String str;
        while((str = reader.readLine()) != null)
          buf.append(str);
        reader.close();
        JSONObject jwk = new JSONObject(buf.toString());
        publicKey = WebPush.importPublicKey(keyAlgorithm, jwk.getString("x"), jwk.getString("y"));
        privateKey = WebPush.importPrivateKey(keyAlgorithm, jwk.getString("d"));
      } catch (IOException | JSONException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
        e.printStackTrace();
      }
    }
    else {
      try {
        KeyPair keyPair = WebPush.generateKeyPair(keyAlgorithm);
        publicKey = (ECPublicKey) keyPair.getPublic();
        privateKey = (ECPrivateKey) keyPair.getPrivate();
        JSONObject jwk = new JSONObject();
        jwk.put("crv", "P-256");
        jwk.put("ext", "true");
        jwk.put("kty", "EC");
        jwk.put("x", Base64.getUrlEncoder().encodeToString(publicKey.getQ().getAffineXCoord().getEncoded()).replaceAll("=+$", ""));
        jwk.put("y", Base64.getUrlEncoder().encodeToString(publicKey.getQ().getAffineYCoord().getEncoded()).replaceAll("=+$", ""));
        jwk.put("d", Base64.getUrlEncoder().encodeToString(privateKey.getD().toByteArray()).replaceAll("=+$", ""));
        try {
          BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file)));
          writer.write(jwk.toString());
          writer.flush();
          writer.close();
        } catch (IOException e) {
          e.printStackTrace();
        }
      } catch (NoSuchAlgorithmException | NoSuchProviderException
          | InvalidAlgorithmParameterException e) {
        e.printStackTrace();
      }
    }
  }

  private String getString(JSONObject json, String key) {
    String str = json.optString(key);
    return "".equals(str) ? null : str;
  }

  private void error(HttpServletResponse resp, String message) {
    try {
      resp.setStatus(HttpServletResponse.SC_NOT_ACCEPTABLE);
      resp.setContentType("application/json; charset=utf-8");
      resp.setCharacterEncoding("UTF-8");
      BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(), "UTF-8"));
      writer.write(new JSONObject().put("error", message).toString());
      writer.flush();
      writer.close();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    String path = req.getPathInfo();
    StringBuffer result = new StringBuffer();
    if("/publicKey".equals(path) && (publicKey != null)) {
      result.append(Base64.getUrlEncoder().encodeToString(publicKey.getQ().getEncoded(false)).replaceAll("=+$", ""));
    }
    else if("/jwk".equals(path) && (publicKey != null)) {
      JSONObject jwk = new JSONObject();
      jwk.put("crv", "P-256");
      jwk.put("ext", "true");
      jwk.put("kty", "EC");
      jwk.put("x", Base64.getUrlEncoder().encodeToString(publicKey.getQ().getAffineXCoord().getEncoded()).replaceAll("=+$", ""));
      jwk.put("y", Base64.getUrlEncoder().encodeToString(publicKey.getQ().getAffineYCoord().getEncoded()).replaceAll("=+$", ""));
      result.append(jwk.toString());
    }
    resp.setStatus(result.length() > 0 ? HttpServletResponse.SC_OK : HttpServletResponse.SC_NOT_FOUND);
    BufferedWriter writer = new BufferedWriter(resp.getWriter());
    writer.write(result.toString());
    writer.flush();
    writer.close();
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    BufferedReader reader = new BufferedReader(new InputStreamReader(req.getInputStream(), "UTF-8"));
    String buf, input = "";
    while((buf = reader.readLine()) != null)
      input += buf;
    reader.close();

    try {
      JSONObject json = new JSONObject(input);
      String endpoint = json.optString("endpoint");
      String key = getString(json, "key");
      String auth = getString(json, "auth");
      String message = getString(json, "message");
      JSONObject info = json.optJSONObject("jwt");
      int version = json.optInt("version", 0);

      if("".equals(endpoint)) {
        error(resp, "empty endpoint");
        return;
      }

      JSONObject result = new JSONObject().put("error", "webpush not invoked");
      // Chrome
      if(endpoint.startsWith(WebPush.GCM_URL)) {
        // Chrome 42-48: GCM
        if((key == null) || (auth == null))
          result = WebPush.sendPushViaGoogleCloudMessaging(
              endpoint.replaceAll("^" + WebPush.GCM_URL + "/", ""));
        // Chrome 49+: Web Push via GCM Server
        else
          result = WebPush.sendWebPush(
              key,
              auth,
              endpoint.replaceAll("^" + WebPush.GCM_URL, WebPush.GCM_WEBPUSH_ENDPOINT),
              message,
              version,
              info);
      }
      // Firefox 44+: Web Push via Mozilla's AutoPush Endpoint
      else
        result = WebPush.sendWebPush(key, auth, endpoint, message, version, info);

      resp.setStatus(HttpServletResponse.SC_OK);
      resp.setContentType("application/json; charset=utf-8");
      resp.setCharacterEncoding("UTF-8");
      BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(), "UTF-8"));
      writer.write(result.toString());
      writer.flush();
      writer.close();
    } catch (JSONException e) {
      e.printStackTrace();
      error(resp, "malformed and/or insufficient parameter(s)");
    }
  }
}