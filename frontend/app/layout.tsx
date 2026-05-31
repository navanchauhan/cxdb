import type { Metadata } from 'next';
import { ThemeProvider } from '@/lib/themes';
import './globals.css';

export const metadata: Metadata = {
  title: 'CXDB - Context Debugger',
  description: 'AI Context Store - Turn DAG Viewer',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-theme-bg text-theme-text min-h-screen">
        <ThemeProvider>
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
