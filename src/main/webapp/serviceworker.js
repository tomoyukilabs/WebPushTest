const showNotification = body => {
  return self.registration.showNotification('WebPushTest', {
    icon: 'image/icon.png',
    body: body || '(with empty payload)',
    vibrate: [400,100,400]
  });
};

const receivePush = evt => {
  var data = '';

  if(evt.data) {
    data = evt.data.text();
  }
  if('showNotification' in self.registration) {
    evt.waitUntil(showNotification(data));
  }
};

self.addEventListener('push', receivePush, false);
