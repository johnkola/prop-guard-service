import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Removed 'export' output - using development server
  images: {
    unoptimized: true
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  turbo: {
    root: __dirname
  },
};

export default nextConfig;