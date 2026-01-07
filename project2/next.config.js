/** @type {import('next').NextConfig} */
const nextConfig = {
  // Remove static export to enable server-side API routes
  // output: 'export',
  eslint: {
    ignoreDuringBuilds: true,
  },
  images: { unoptimized: true },
  // Configure server to listen on port 4000
  experimental: {
    serverComponentsExternalPackages: [],
  },
};

module.exports = nextConfig;
