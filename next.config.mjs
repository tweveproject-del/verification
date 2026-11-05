/** @type {import('next').NextConfig} */
const isDev = process.env.NODE_ENV === 'development';

const nextConfig = {
  reactStrictMode: true,
  ...(!isDev ? { output: 'export' } : {}),
  async rewrites() {
    if (!isDev) return [];
    return [
      {
        source: '/api/tunneltweak/:path*',
        destination: 'https://tunneltweak.com/api/:path*',
      },
    ];
  },
};

export default nextConfig;
