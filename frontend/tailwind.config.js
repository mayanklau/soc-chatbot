/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'cyber': {
          'bg': '#0a0e17',
          'surface': '#111827',
          'border': '#1e2a3a',
          'accent': '#00ff88',
          'accent-dim': '#00cc6a',
          'warning': '#ff6b35',
          'critical': '#ff3366',
          'info': '#00d4ff',
          'text': '#e5e7eb',
          'muted': '#6b7280'
        }
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'monospace'],
        'sans': ['Inter', 'sans-serif']
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'scan': 'scan 2s linear infinite'
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px #00ff88, 0 0 10px #00ff88' },
          '100%': { boxShadow: '0 0 10px #00ff88, 0 0 20px #00ff88, 0 0 30px #00ff88' }
        },
        scan: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' }
        }
      }
    },
  },
  plugins: [],
}
