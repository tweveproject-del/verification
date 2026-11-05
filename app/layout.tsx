import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Tweve Tunnel — Cloud Config Inspector & Server Diagnostics",
  description:
    "Verify Tweve Tunnel Cloud UUIDs, .twt & .tut files, inspect decrypted parameters, and diagnose why a VPN server or configuration is failing to connect.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

