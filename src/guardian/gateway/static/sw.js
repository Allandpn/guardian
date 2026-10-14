// Service worker mínimo: permite instalar a PWA. Não guarda nada da API (dados sensíveis) em cache.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
