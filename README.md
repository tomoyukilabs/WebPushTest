# WebPushTest

This repository consists of an application server implementation for Web Push, running on Jetty 9.x.

## TO DO
Before buidling this with Maven, the following parameters must be set to your own:

* `GCM_SERVER_KEY` in `src/jp/othersight/WebPush.java` - your GCM API key
* `gcm_sender_id` in `src/main/webapp/manifest.json` - your Google API Project number

## Demo Site
Please try https://labs.othersight.jp/webpushtest/