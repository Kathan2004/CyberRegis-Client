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
  // Proxy API calls to Flask backend (fallback for any /api/backend/* routes)
  async rewrites() {
    return [
      {
        source: '/api/backend/:path*',
        destination: `${process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:5000'}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
