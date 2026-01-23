const CACHE_NAME = 'html-editor-pwa-v1';

// Lista de arquivos para armazenar em cache
const urlsToCache = [
  '/', // É mais seguro usar ./ para a raiz
  'index.html',
  'manifest.json',
  'icon-192x192.png',
  'icon-512x512.png',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css',
  'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap'
];

// Evento de instalação: abre o cache e armazena os arquivos
self.addEventListener('install', event => {
  // Força o Service Worker a se tornar ativo imediatamente
  self.skipWaiting();
  
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Cache aberto com sucesso');
        return cache.addAll(urlsToCache);
      })
  );
});

// Evento de ativação: limpa caches antigos
self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            console.log('Deletando cache antigo:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => self.clients.claim()) // Assume o controle das abas abertas imediatamente
  );
});

// Evento de fetch: serve arquivos do cache primeiro (Cache First)
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Se a resposta estiver no cache, retorna ela
        if (response) {
          return response;
        }
        
        // Caso contrário, busca na rede
        return fetch(event.request).catch(() => {
          // Opcional: Aqui você poderia retornar uma página offline caso a rede falhe
          // if (event.request.mode === 'navigate') return caches.match('offline.html');
        });
      })
  );
});
