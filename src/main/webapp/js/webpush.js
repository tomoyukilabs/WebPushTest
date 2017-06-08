'use strict';

let _ = function(id) { return document.getElementById(id); }

let subscription = null;
let authType = 'vapid';
let serverKey = null;

function encodeBase64URL(buffer) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBase64URL(str) {
  let dec = atob(str.replace(/\-/g, '+').replace(/_/g, '/'));
  let buffer = new Uint8Array(dec.length);
  for(let i = 0 ; i < dec.length ; i++)
    buffer[i] = dec.charCodeAt(i);
  return buffer;
}

function enablePushRequest(sub) {
  subscription = sub;
  _('subscribe').classList.add('subscribing');
  _('push').disabled = false;
  _('authtype').disabled = true;
  _('endpoint').textContent = subscription.endpoint;
  if('getKey' in subscription) {
    _('message').disabled = false;
    _('key').textContent = encodeBase64URL(subscription.getKey('p256dh'));
    try {
      _('auth').textContent = encodeBase64URL(subscription.getKey('auth'));
    } catch(e) {
    }
  }
}

function disablePushRequest() {
  _('subscribe').classList.remove('subscribing');
  _('message').disabled = true;
  _('message').value = '';
  _('push').disabled = true;
  _('authtype').disabled = false;
  _('endpoint').textContent = '';
  _('key').textContent = '';
  _('auth').textContent = '';
  _('response').classList.remove('error');
  _('statuscode').textContent = '';
  _('detail').textContent = '';
}

function requestPushUnsubcription() {
  if(subscription) {
    subscription.unsubscribe();
    subscription = null;
    disablePushRequest();
  }
}

function getSubscription(sub) {
  delete _('status').dataset.error;
  _('status').classList.remove('subscribe-error');
  if(sub) {
    enablePushRequest(sub);
  }
  else {
    disablePushRequest();
  }
}

function errorSubscription(err) {
  _('status').dataset.error = err;
  _('status').classList.add('subscribe-error');
}

function requestPushSubscription(registration) {
  let opt = {
    userVisible: true, // for Chrome 42-44
    userVisibleOnly: true
  };
  if(authType === 'vapid')
    opt.applicationServerKey = serverKey;
  return registration.pushManager.subscribe(opt).then(getSubscription, errorSubscription);
}

function checkPushPermission(evt) {
  let state = evt.state || evt.status;
  if(state !== 'denied')
    navigator.serviceWorker.ready.then(requestPushSubscription);
}

function requestPushPermission() {
  if('permissions' in navigator) 
    navigator.permissions.query({
      name: 'push',
      userVisibleOnly: true
    }).then(checkPushPermission);
  else if(Notification.permission !== 'denied') {
    navigator.serviceWorker.ready.then(requestPushSubscription);
  }
}

function requestNotificationPermission() {
  Notification.requestPermission(function(permission) {
    if(permission !== 'denied') {
      requestPushPermission();
    }
  });
}

function togglePushSubscription() {
  if(!_('subscribe').classList.contains('subscribing')) {
    requestNotificationPermission();
  }
  else {
    requestPushUnsubcription();
  }
}

function serviceWorkerReady(registration) {
  if('pushManager' in registration) {
    var s = _('subscribe');
    s.disabled = false;
    s.classList.remove('subscribing');
    registration.pushManager.getSubscription().then(getSubscription);
  }
  else {
    _('status').classList.add('no-push');
  }
}

function requestPushNotification() {
  if(subscription) {
    let arg = {
      endpoint: subscription.endpoint,
      message: _('message').value
    };
    if('getKey' in subscription) {
      arg.key = encodeBase64URL(subscription.getKey('p256dh'));
      try {
        arg.auth = encodeBase64URL(subscription.getKey('auth'));
        const useAesgcm = navigator.userAgent.match(/Firefox\/(\d+)/) ? ((parseInt(RegExp.$1) >= 46) ? 1 : 0) :
          ((navigator.userAgent.match(/Chrome\/(\d+)/) ? ((parseInt(RegExp.$1) >= 50) ? 1 : 0) : 0));
        const encodings = PushManager.supportedContentEncodings;
        const idx = encodings instanceof Array ? encodings.indexOf('aes128gcm') : -1;
        arg.contentEncoding = idx >= 0 ? 'aes128gcm' : (useAesgcm ? 'aesgcm' : 'aesgcm128');          
      } catch (e) {
      }
    }
    if(authType === 'vapid') {
      arg.jwt = {
        aud: new URL(subscription.endpoint).origin,
        sub: location.href
      };
    }
    fetch('./push', {
      method: 'POST',
      body: JSON.stringify(arg),
      headers: { 'Content-Type': 'application/json' }
    }).then(resp => {
      return resp.json();
    }).then(json => {
      if('error' in json) {
        _('response').classList.add('error');
        _('servererror').textContent = json.error;
      }
      else {
        _('response').classList.remove('error');
        _('servererror').textContent = '';
      }
      _('statuscode').textContent = json.status;
      _('detail').textContent = json.response;
    }, () => {
      _('response').classList.add('error');
      _('statuscode').textContent = '(N/A)';
      _('servererror').textContent = 'malformed JSON returned';
    });
  }
}

function setAuthType(evt) {
  let link;
  authType = evt.currentTarget.value;
  localStorage.setItem('authType', authType);
  switch(authType) {
  case 'vapid':
    link = document.querySelector('link[rel="manifest"]');
    if(link)
      link.parentNode.removeChild(link);
    break;
  case 'gcm':
    link = document.createElement('link');
    link.rel = 'manifest';
    link.href = 'manifest.json';
    document.querySelector('head').appendChild(link);
    break;
  }
}

function setServerKey(key) {
  serverKey = decodeBase64URL(key);
  navigator.serviceWorker.ready.then(serviceWorkerReady);
}

function getServerKey(resp) {
  return resp.text();
}

function init() {
  if('serviceWorker' in navigator) {
    authType = localStorage.getItem('authType');
    if(authType) {
      setAuthType({ currentTarget: { value: authType }});
      _('auth' + authType).checked = true;
    }
    _('subscribe').addEventListener('click', togglePushSubscription, false);
    _('push').addEventListener('click', requestPushNotification, false);
    _('authvapid').addEventListener('change', setAuthType, false);
    _('authgcm').addEventListener('change', setAuthType, false);
    fetch('./push/publicKey').then(getServerKey).then(setServerKey);
    navigator.serviceWorker.register('serviceworker.js');
  }
  else {
    _('status').classList.add('no-sw');
  }
}

window.addEventListener('load', init, false);