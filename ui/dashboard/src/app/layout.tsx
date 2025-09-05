import type { Metadata, Viewport } from "next";
import { Inter, Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import DashboardLayout from "../components/layout/DashboardLayout";
import "../lib/logger"; // Initialize logger

const inter = Inter({
    subsets: ["latin"],
    display: 'swap',
    variable: '--font-inter',
});

const geistSans = Geist({
    variable: "--font-geist-sans",
    subsets: ["latin"],
    display: 'swap',
});

const geistMono = Geist_Mono({
    variable: "--font-geist-mono",
    subsets: ["latin"],
    display: 'swap',
});

export const viewport: Viewport = {
    width: 'device-width',
    initialScale: 1,
};

export const metadata: Metadata = {
    title: "PropGuard - Secrets Management",
    description: "Secure secrets management and configuration service with enterprise-grade security.",
    keywords: ["secrets management", "security", "encryption", "vault", "configuration"],
    authors: [{ name: "PropGuard Team" }],
    robots: "index, follow",
    openGraph: {
        title: "PropGuard - Secrets Management",
        description: "Secure secrets management with AES-256 encryption and audit trails",
        type: "website",
    }
};

export default function RootLayout({
                                       children,
                                   }: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en" suppressHydrationWarning>
        <head>
            <link rel="icon" href="/favicon.ico" sizes="any" />
            <meta name="theme-color" content="#667eea" />
        </head>
        <body
            className={`${geistSans.variable} ${geistMono.variable} ${inter.variable} antialiased`}
            suppressHydrationWarning
        >
        {children}
        </body>
        </html>
    );
}