import type { Metadata } from "next";
import { CopilotKit } from "@copilotkit/react-core";
import "@copilotkit/react-ui/styles.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "Find Evil — Forensic Agent",
  description: "Investigation forensique mémoire pilotée par un agent via Splunk MCP Server",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="fr">
      <body>
        <CopilotKit runtimeUrl="/api/copilotkit" agent="forensic_agent">
          {children}
        </CopilotKit>
      </body>
    </html>
  );
}
