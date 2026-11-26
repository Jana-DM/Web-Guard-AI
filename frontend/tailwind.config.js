/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#060a13',
          surface: '#0c1322',
          card: '#111a2e',
          border: '#1e293b',
          accent: '#06b6d4',
          emerald: '#10b981',
          amber: '#f59e0b',
          crimson: '#ef4444',
          violet: '#8b5cf6',
        },
      },
    },
  },
  plugins: [],
}
