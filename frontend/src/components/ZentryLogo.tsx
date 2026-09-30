import React from "react";

interface ZentryLogoProps {
  className?: string;
  size?: number;
}

export const ZentryLogo: React.FC<ZentryLogoProps> = ({
  className = "w-8 h-8",
  size = 32,
}) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 40 40"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <defs>
        {/* Exterior Shield Gradient */}
        <linearGradient id="zentryShieldGrad" x1="0" y1="0" x2="40" y2="40" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38BDF8" />
          <stop offset="50%" stopColor="#3B82F6" />
          <stop offset="100%" stopColor="#1E40AF" />
        </linearGradient>

        {/* Glow Filter */}
        <filter id="zentryGlow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="1.5" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>

        {/* Core 'Z' Bolt Gradient */}
        <linearGradient id="zentryCoreZ" x1="8" y1="6" x2="32" y2="34" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#FFFFFF" />
          <stop offset="35%" stopColor="#60A5FA" />
          <stop offset="100%" stopColor="#0284C7" />
        </linearGradient>

        {/* Specular Edge Highlight */}
        <linearGradient id="zentrySpecular" x1="0" y1="0" x2="20" y2="10" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.8" />
          <stop offset="100%" stopColor="#FFFFFF" stopOpacity="0" />
        </linearGradient>
      </defs>

      {/* Outer Tactical Hexagonal Shield Frame */}
      <path
        d="M20 2L36 8V20C36 29.5 29.2 38.1 20 40C10.8 38.1 4 29.5 4 20V8L20 2Z"
        fill="#0B0F14"
        stroke="url(#zentryShieldGrad)"
        strokeWidth="1.75"
        strokeLinejoin="round"
      />

      {/* Inner Shield Bevel Ring */}
      <path
        d="M20 5L33 10V19.5C33 27.2 27.5 34.2 20 36C12.5 34.2 7 27.2 7 19.5V10L20 5Z"
        fill="rgba(59, 130, 246, 0.06)"
        stroke="rgba(56, 189, 248, 0.25)"
        strokeWidth="1"
      />

      {/* Cybernetic Geometric 'Z' Monogram */}
      <path
        d="M12 12H28L18 24H28V27H12L22 15H12V12Z"
        fill="url(#zentryCoreZ)"
      />

      {/* Top Left Specular Highlight Accent */}
      <path
        d="M20 3.5L34 8.8L32 10.5L20 6L8 10.5L6 8.8L20 3.5Z"
        fill="url(#zentrySpecular)"
        opacity="0.6"
      />

      {/* Center Tactical Nexus Dot */}
      <circle cx="20" cy="19.5" r="1.5" fill="#38BDF8" className="animate-pulse" />
    </svg>
  );
};
