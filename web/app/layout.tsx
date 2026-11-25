import type { Metadata } from "next";
import "@fontsource-variable/onest/index.css";
import "@fontsource-variable/jetbrains-mono/index.css";
import "./globals.css";
import { LiveProvider } from "@/lib/live";
import { Shell } from "@/components/Shell";

export const metadata: Metadata = {
  title: "NetWatch: network intrusion detection",
  description: "Suricata signatures, a flow classifier, and automatic blocking, with a live dashboard.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <LiveProvider>
          <Shell>{children}</Shell>
        </LiveProvider>
      </body>
    </html>
  );
}
