import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Lead Generator — Exposure Intelligence",
  description:
    "Sales prospecting built from public internet scan data. Companies ranked by what attackers are actively exploiting, not by severity scores.",
};

export default function RootLayout({
  children,
}: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
