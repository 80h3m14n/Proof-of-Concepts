/* global workbox */
importScripts(
  "https://storage.googleapis.com/workbox-cdn/releases/7.1.0/workbox-sw.js",
);

if (workbox) {
  workbox.core.setCacheNameDetails({ prefix: "poc-atlas" });

  workbox.precaching.precacheAndRoute([
    { url: "/", revision: "1" },
    { url: "index.html", revision: "2" },
    { url: "styles.css", revision: "2" },
    { url: "app.js", revision: "1" },
    { url: "manifest.webmanifest", revision: "1" },
    { url: "data/manifest.json", revision: "1" },
    { url: "data/shards/2024.json", revision: "1" },
    { url: "data/shards/2025.json", revision: "1" },
    { url: "data/shards/2026.json", revision: "1" },
    { url: "icons/poc-atlas.svg", revision: "1" },
  ]);

  workbox.routing.registerRoute(
    ({ request, url }) =>
      request.mode === "navigate" || url.pathname.endsWith(".html"),
    new workbox.strategies.NetworkFirst({
      cacheName: "pages-cache",
    }),
  );

  workbox.routing.registerRoute(
    ({ url }) =>
      url.pathname.startsWith("/data/") ||
      /^\/CVE-\d{4}-\d+\/(README\.md|exploit\.[a-z0-9]+)$/i.test(url.pathname),
    new workbox.strategies.StaleWhileRevalidate({
      cacheName: "content-cache",
    }),
  );

  workbox.routing.registerRoute(
    ({ request }) =>
      request.destination === "style" ||
      request.destination === "script" ||
      request.destination === "font",
    new workbox.strategies.StaleWhileRevalidate({
      cacheName: "assets-cache",
    }),
  );
}
