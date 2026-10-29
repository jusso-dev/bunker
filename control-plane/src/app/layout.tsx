import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "Bunker · Recovery control",
  description: "Backup policies, restore approvals, and recovery evidence.",
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
