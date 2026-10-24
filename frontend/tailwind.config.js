/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        canvas: '#0d1117',
        surface: '#161b22',
        raised: '#1c2128',
        line: { DEFAULT: '#2f3741', strong: '#444c56' },
        ink: { DEFAULT: '#e6edf3', dim: '#8d96a0', faint: '#6a737d' },
        accent: { DEFAULT: '#4493f8', hover: '#5da2fa', tint: 'rgba(68,147,248,0.12)' },
        danger: { DEFAULT: '#f85149', tint: 'rgba(248,81,73,0.10)' },
        warn: { DEFAULT: '#d29922', tint: 'rgba(210,153,34,0.10)' },
        good: { DEFAULT: '#3fb950', tint: 'rgba(63,185,80,0.10)' },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '8px',
      },
    },
  },
  plugins: [],
}
