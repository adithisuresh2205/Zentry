import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "SentinelGate — Security Dashboard",
  description: "Zero-Trust Web Application Security Gateway — Real-Time Monitoring",
  robots: "noindex, nofollow", // Dashboard should not be indexed
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${inter.variable} ${jetbrainsMono.variable} bg-sentinel-bg text-sentinel-text antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
