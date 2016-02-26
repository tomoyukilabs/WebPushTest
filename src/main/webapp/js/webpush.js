var _ = function(id) { return document.getElementById(id); }

function serviceWorkerReady(registration) {
  console.log('registered');
}

function registerServiceWorker() {
  if(!('serviceWorker' in navigator)) {
    _('status').classList.add('no-sw');
  }
  else {
    navigator.serviceWorker.ready.then(serviceWorkerReady);
    navigator.serviceWorker.register('serviceworker.js');
  }
}

window.addEventListener('load', registerServiceWorker, false);