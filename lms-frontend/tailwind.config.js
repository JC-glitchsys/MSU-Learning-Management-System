/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      // Dito natin ine-extend ang configuration para basahin ang arbitrary metrics natin
      spacing: {
        '64': '16rem',
        '68': '17rem', // Ini-whitelist natin para gumana ang structural shell framework natin
      }
    },
  },
  plugins: [],
}