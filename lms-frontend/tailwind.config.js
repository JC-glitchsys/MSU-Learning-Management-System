/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: { sans: ['Inter', 'sans-serif'] },
      colors: {
        maroon: { DEFAULT: '#800000', dark: '#5C0000', light: '#FDF0F0' },
        text: { main: '#202124', secondary: '#5F6368' },
        border: '#DADCE0',
        bg: '#F8F9FA',
      },
      // Dito natin ine-extend ang configuration para basahin ang arbitrary metrics natin
      spacing: {
        '64': '16rem',
        '68': '17rem', // Ini-whitelist natin para gumana ang structural shell framework natin
      }
    },
  },
  plugins: [],
}
