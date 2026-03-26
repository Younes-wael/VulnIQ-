/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        brand:    '#6366f1',
        critical: '#ef4444',
        high:     '#f97316',
        medium:   '#eab308',
        low:      '#22c55e',
        surface:  '#0f172a',
        card:     '#1e293b',
        border:   '#334155',
      },
    },
  },
  plugins: [],
}
