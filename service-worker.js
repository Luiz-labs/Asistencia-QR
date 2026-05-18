const CACHE_NAME = "asistia-pwa-v0.9.6-beta-10014"

const PRECACHE_URLS = [
  "/",
  "/index.html",
  "/style.css",
  "/app.js",
  "/manifest.webmanifest",
  "/pwa-register.js",
  "/icon-192.png",
  "/icon-512.png",
  "/apple-touch-icon.png",
  "/asistIA_logo.png",
  "/24_logo.png",
  "/B129logo.png",
  "/asistencia/index.html",
  "/asistencia/style.css",
  "/asistencia/app.js",
  "/staff-asistencia/index.html",
  "/staff-asistencia/style.css",
  "/staff-asistencia/app.js"
]

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  )
})

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  )
})

function resolveNavigationFallback(pathname = "/") {
  if (pathname.includes("/staff-asistencia")) return "/staff-asistencia/index.html"
  if (pathname.includes("/asistencia")) return "/asistencia/index.html"
  return "/index.html"
}

self.addEventListener("fetch", event => {
  const request = event.request
  if (request.method !== "GET") return

  const url = new URL(request.url)
  if (url.origin !== self.location.origin) return

  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).then(response => {
        if (response && response.ok) {
          const responseClone = response.clone()
          caches.open(CACHE_NAME).then(cache => cache.put(request, responseClone))
        }
        return response
      }).catch(async () => {
        const cached = await caches.match(request)
        if (cached) return cached
        return caches.match(resolveNavigationFallback(url.pathname))
      })
    )
    return
  }

  if (!PRECACHE_URLS.includes(url.pathname)) return

  event.respondWith(
    caches.match(request).then(cached => {
      if (cached) return cached
      return fetch(request).then(response => {
        if (response && response.ok) {
          const responseClone = response.clone()
          caches.open(CACHE_NAME).then(cache => cache.put(request, responseClone))
        }
        return response
      })
    })
  )
})
