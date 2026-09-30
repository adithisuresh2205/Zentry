import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Zentry Zero-Trust Tactical Palette
        zentry: {
          bg: {
            DEFAULT: "#080B10",
            deep: "#0B0F14",
            elevated: "#0E131A",
          },
          surface: {
            DEFAULT: "#10151C",
            panel: "#131922",
            card: "#171D26",
          },
          border: {
            subtle: "#202832",
            DEFAULT: "#27313C",
            active: "#3B82F6",
          },
          accent: {
            blue: "#3B82F6",
            cyan: "#38BDF8",
          },
          status: {
            allowed: "#10B981",
            warning: "#F59E0B",
            blocked: "#EF4444",
          },
          text: {
            primary: "#F3F4F6",
            secondary: "#9CA3AF",
            muted: "#6B7280",
          },
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "SFMono-Regular", "Menlo", "monospace"],
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "sans-serif"],
      },
    },
  },
  plugins: [],
};

export default config;
