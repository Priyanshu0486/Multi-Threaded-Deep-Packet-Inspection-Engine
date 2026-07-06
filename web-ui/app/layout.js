import './globals.css';

export const metadata = {
  title: 'DPI Engine | Traffic Analyzer',
  description: 'Deep Packet Inspection Engine Web Interface for analyzing and filtering network traffic.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <div className="background-glow"></div>
        <div className="background-glow secondary"></div>
        {children}
      </body>
    </html>
  );
}
