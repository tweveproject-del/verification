import "./globals.css";
import "./generated-utilities.css";
import type { Metadata, Viewport } from "next";

export const metadata: Metadata = {
  title: "Tweve Tunnel — Cloud Config Inspector & Server Diagnostics",
  description:
    "Verify Tweve Tunnel Cloud UUIDs, .twt & .tut files, inspect decrypted parameters, and diagnose why a VPN server or configuration is failing to connect.",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
  viewportFit: "cover",
  themeColor: "#04080e",
  colorScheme: "dark",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
      </head>
      <body>{children}</body>
    </html>
  );
}

