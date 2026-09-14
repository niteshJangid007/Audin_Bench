"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert,
  GitBranch,
  FileSearch,
  CheckSquare,
  Sliders,
  FileText,
  Github,
  Terminal,
  Activity,
} from "lucide-react";

export default function Navbar() {
  const pathname = usePathname();

  const navItems = [
    { name: "Dashboard", href: "/", icon: Activity },
    { name: "Repositories", href: "/repositories", icon: GitBranch },
    { name: "Audits & Scans", href: "/scans", icon: FileSearch },
    { name: "Findings", href: "/findings", icon: ShieldAlert },
    { name: "Security Policies", href: "/policies", icon: Sliders },
    { name: "Reports", href: "/reports", icon: FileText },
    { name: "GitHub App", href: "/settings/github", icon: Github },
    { name: "Sandbox Workbench", href: "/sandbox", icon: Terminal },
  ];

  return (
    <header className="border-b border-surfaceBorder bg-surface/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo & Name */}
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-md bg-gradient-to-br from-critical to-high flex items-center justify-center shadow-lg shadow-critical/20">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold tracking-wider text-base text-white">
                  AUDIT BENCH
                </span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-surfaceBorder text-primary border border-primary/20">
                  DEVSECOPS GATE
                </span>
              </div>
              <p className="text-[11px] text-gray-400 font-mono">
                DETERMINISTIC OWASP TOP 10 ORCHESTRATION
              </p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="hidden lg:flex items-center gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono transition-colors ${
                    isActive
                      ? "bg-surfaceHover text-primary border border-primary/30 font-semibold shadow-sm"
                      : "text-gray-300 hover:text-white hover:bg-surfaceHover"
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {item.name}
                </Link>
              );
            })}
          </nav>

          {/* Status Indicator */}
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="inline-block w-2 h-2 rounded-full bg-success animate-pulse"></span>
            <span className="text-gray-300 hidden sm:inline">GATE ENGINE ACTIVE</span>
          </div>
        </div>
      </div>
    </header>
  );
}
