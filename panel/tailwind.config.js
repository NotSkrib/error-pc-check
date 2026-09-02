/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        sev: {
          clean: "#16a34a",
          info: "#0891b2",
          low: "#ca8a04",
          medium: "#ea580c",
          high: "#dc2626",
          critical: "#7f1d1d",
        },
      },
    },
  },
  plugins: [],
};
