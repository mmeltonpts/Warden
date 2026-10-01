/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // GAM jobs are spawned from route handlers and the worker; keep them external.
  serverExternalPackages: ['@prisma/client']
  // No serverActions.allowedOrigins list. Server Actions accept a POST when the Origin
  // header matches the Host the request arrived on, and deploy/nginx-warden.conf passes
  // `Host $http_host` — host AND port, exactly as the browser sent them — so every name
  // and address the console is reached by matches itself. A hardcoded list here was a
  // build-time copy of one district's hostnames, and every new name needed a rebuild.
};
export default nextConfig;
