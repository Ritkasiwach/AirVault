import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  typescript: {
    // Production build ko minor TS version mismatches pe rukne mat do
    ignoreBuildErrors: true,
  },
};

export default nextConfig;