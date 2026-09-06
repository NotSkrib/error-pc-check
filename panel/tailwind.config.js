/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['ui-monospace', 'JetBrains Mono', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      colors: {
        brand: {
          DEFAULT: "#e5484d",
          hi: "#f2555b",
          dim: "#8f2c30",
        },
        ink: {
          0: "#07080a",
          1: "#0d0e11",
          2: "#131418",
          3: "#191b20",
          line: "rgba(255,255,255,0.08)",
          line2: "rgba(255,255,255,0.14)",
        },
        fg: {
          DEFAULT: "#e9e9ec",
          mut: "#9a9ca3",
          dim: "#63666e",
        },
        sev: {
          clean: "#37b26a",
          info: "#3aa0d1",
          low: "#d1a33a",
          medium: "#e0803a",
          high: "#e5484d",
          critical: "#ff5b6b",
        },
      },
      boxShadow: {
        card: "0 1px 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.6)",
        glow: "0 0 0 1px rgba(229,72,77,0.35), 0 8px 30px -8px rgba(229,72,77,0.35)",
      },
    },
  },
  plugins: [],
};
