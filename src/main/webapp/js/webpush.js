var _ = function(id) { return document.getElementById(id); }

var subscription = null;

function encodeBase64URL(buffer) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_');
}

function enablePushRequest(sub) {
  subscription = sub;
  _('subscribe').classList.add('subscribing');
  _('push').disabled = false;
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
  _('endpoint').textContent = '';
  _('key').textContent = '';
  _('auth').textContent = '';
}

function requestPushUnsubcription() {
  if(subscription) {
    subscription.unsubscribe();
    subscription = null;
    disablePushRequest();
  }
}

function getSubscription(sub) {
  if(sub) {
    enablePushRequest(sub);
  }
  else {
    disablePushRequest();
  }
}

function requestPushSubscription(registration) {
  return registration.pushManager.subscribe({
    userVisible: true, // for Chrome 42-44
    userVisibleOnly: true
  }).then(getSubscription);
}

function checkPushPermission(evt) {
  var state = evt.state || evt.status;
  if(state !== 'deined')
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
    var arg = {
      endpoint: subscription.endpoint,
      message: escape(_('message').value)
    };
    if('getKey' in subscription) {
      arg.key = encodeBase64URL(subscription.getKey('p256dh'));
      try {
        arg.auth = encodeBase64URL(subscription.getKey('auth'));
        arg.version = navigator.userAgent.match(/Firefox\/(\d+)/) ? ((parseInt(RegExp.$1) >= 48) ? 1 : 0) :
          ((navigator.userAgent.match(/Chrome\/(\d+)/) ? ((parseInt(RegExp.$1) >= 50) ? 1 : 0) : 0))
      } catch (e) {
      }
    }
    var xhr = new XMLHttpRequest();
    xhr.open('POST', './push');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify(arg));
  }
}

function init() {
  if('serviceWorker' in navigator) {
    _('subscribe').addEventListener('click', togglePushSubscription, false);
    _('push').addEventListener('click', requestPushNotification, false);
    navigator.serviceWorker.ready.then(serviceWorkerReady);
    navigator.serviceWorker.register('serviceworker.js');
  }
  else {
    _('status').classList.add('no-sw');
  }
}

window.addEventListener('load', init, false);