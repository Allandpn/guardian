// Service worker: permite instalar a PWA e mostra os avisos de Web Push. Não guarda nada da API (dados sensíveis) em cache.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { /* aviso sem corpo */ }
  e.waitUntil(self.registration.showNotification(String(d.title || 'NotToday Guardian'), {
    body: String(d.body || ''),
    tag: d.tag ? String(d.tag) : undefined,
    icon: '/icon.svg',
    data: { url: '/' },
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) if ('focus' in c) return c.focus();
    return self.clients.openWindow('/');
  }));
});
