/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        siem: {
          bg: '#080b11',
          panel: '#0f172a',
          card: '#131d31',
          border: '#1e293b',
          hover: '#1e293b',
          cyan: '#06b6d4',
          emerald: '#10b981',
          amber: '#f59e0b',
          rose: '#f43f5e',
          purple: '#8b5cf6'
        }
      }
    },
  },
  plugins: [],
}
