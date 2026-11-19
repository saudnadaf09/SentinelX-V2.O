/** SentinelX design tokens: cool slate surfaces, steel-blue accent, severity-coded signal colours. */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#0d1218', panel: '#141b24', raised: '#1b2430', line: '#2a3544',
        fg: '#e3e8ef', muted: '#8793a6', accent: '#6aa6ff', accentdim: '#2c4a7a',
        sev: { critical: '#ff5c7a', high: '#ff9248', medium: '#f2c94c', low: '#5ab0f0', informational: '#8793a6' },
        ok: '#4cc38a', warn: '#f2c94c', bad: '#ff5c7a',
      },
      fontFamily: {
        sans: ['"Segoe UI Variable Text"', '"Segoe UI"', 'system-ui', '-apple-system', 'Roboto', 'sans-serif'],
        mono: ['"Cascadia Mono"', 'ui-monospace', 'Consolas', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
}
