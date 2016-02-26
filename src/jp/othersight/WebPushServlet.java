package jp.othersight;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Security;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONException;
import org.json.JSONObject;

@WebServlet(name="WebPushServlet", urlPatterns="/push")
public class WebPushServlet extends HttpServlet {

  /**
   * 
   */
  private static final long serialVersionUID = 2888859180954573814L;

  public WebPushServlet() {
    Security.addProvider(new BouncyCastleProvider());
  }

  private String getString(JSONObject json, String key) {
    String str = json.optString(key);
    return "".equals(str) ? null : str;
  }

  private void error(HttpServletResponse resp) {
    resp.setStatus(HttpServletResponse.SC_NOT_ACCEPTABLE);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    BufferedReader reader = new BufferedReader(new InputStreamReader(req.getInputStream()));
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

      if("".equals(endpoint)) {
        error(resp);
        return;
      }

      // Chrome
      if(endpoint.startsWith(WebPush.GCM_URL)) {
        // Chrome 42-48: GCM
        if((key == null) || (auth == null))
          WebPush.sendPushViaGoogleCloudMessaging(
              endpoint.replaceAll("^" + WebPush.GCM_URL + "/", ""));
        // Chrome 49+: Web Push via GCM Server
        else
          WebPush.sendWebPush(
              key,
              auth,
              endpoint.replaceAll("^" + WebPush.GCM_URL, WebPush.GCM_WEBPUSH_ENDPOINT),
              message,
              1);
      }
      // Firefox 44+: Web Push via Mozilla's AutoPush Endpoint
      else
        WebPush.sendWebPush(key, auth, endpoint, message, 0);

      resp.setStatus(HttpServletResponse.SC_OK);
    } catch (JSONException e) {
      e.printStackTrace();
      error(resp);
    }
  }
}