/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        dark: {
          bg: '#0a0a0a',
          card: '#141414',
          border: '#2a2a2a',
          hover: '#1f1f1f',
        },
        accent: {
          primary: '#00ff9f',
          secondary: '#00ccff',
          danger: '#ff3b3b',
          warning: '#ffaa00',
        }
      }
    },
  },
  plugins: [],
}
