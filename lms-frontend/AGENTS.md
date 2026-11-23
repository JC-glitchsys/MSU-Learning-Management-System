# Frontend project guide

## Project

- This repository is the frontend for the MSU Learning Management System.
- It is a Vue 3 single-page application built with Vite and JavaScript ES modules.
- Use Vue Single File Components (`.vue`) for views, layouts, and reusable UI.
- Routing is handled by Vue Router. Firebase provides Authentication, Firestore, and Storage.
- Tailwind CSS v4 is integrated through `@tailwindcss/vite`; global styles enter through `src/assets/main.css`.
- The Vite `@` alias points to `src/`.

## Structure

- `src/Pages/` contains route-level pages, grouped by `admin`, `instructor`, `student`, `auth`, and `common`.
- `src/components/common/` contains shared UI components.
- `src/Layouts/` contains authenticated application and auth layouts.
- `src/router/index.js` defines routes, role metadata, and the navigation guard.
- `src/firebase/config.js` initializes Firebase and exports `auth`, `db`, and `storage`.
- `src/utils/` contains shared helpers.
- `src/assets/main.css` is the main global stylesheet; `src/style.css` is a legacy import of it.

Keep imports consistent with the repository's actual path casing (`Pages`, `Layouts`, `components`). Some folders use uppercase names, so preserve exact casing in imports for case-sensitive environments.

## Implementation conventions

- Follow the existing Vue component and JavaScript style in nearby files. Keep changes focused and reuse existing common components where practical.
- Keep page-specific behavior in its page component; move genuinely shared behavior into `components/common/` or `utils/`.
- Add or change pages by updating `src/router/index.js`. Role-restricted routes should retain the existing `requiresAuth` and `role` metadata conventions.
- Use the existing result-message helper/component for user-facing operation feedback when it fits the change.
- Follow current Tailwind and stylesheet conventions; avoid introducing another styling framework or duplicate global entry point.
- Do not hardcode private credentials or secrets. Keep Firebase initialization centralized in `src/firebase/config.js`; use environment configuration for any new secret or environment-specific value.
- Preserve existing behavior and unrelated user changes. Avoid broad rewrites when a focused change is sufficient.

## Visual design guidelines

- Keep the interface calm, readable, and consistent with the existing MSU maroon and neutral palette. Use maroon for primary actions, active navigation, and small emphasis; use neutral colors for most surfaces and text.
- Reuse the existing theme tokens in `src/assets/main.css`: `--lms-ink`, `--lms-muted`, `--lms-border`, `--lms-maroon`, `--lms-maroon-hover`, `--lms-canvas`, and `--lms-surface`. Prefer these tokens over adding one-off colors.
- Use clear surface hierarchy: a light gray page canvas, white content surfaces, and subtle neutral borders. Cards and panels should have a visible 1px border (normally `--lms-border` or a softer neutral), with padding consistent with nearby components.
- Use consistent corner radii: 8px for inputs, buttons, compact controls, tables, and standard cards; reserve larger radii (12–16px) for prominent outer panels or special feature cards. Use fully rounded corners only for circular avatars or pill-shaped status controls.
- Keep spacing on a predictable scale, favoring 4px increments (8, 12, 16, 24, 32). Align card content and page headings with adjacent sections; allow tighter spacing on mobile.
- Use subtle borders and restrained hover states to distinguish interactive elements. Avoid heavy shadows, gradients, decorative motion, and multiple competing accent colors; the current stylesheet intentionally keeps shadows and movement minimal.
- Inputs and selects should have a visible neutral border, rounded corners, and a clear keyboard focus ring using a low-opacity maroon tint. Do not remove focus indicators.
- Maintain readable contrast and the established type hierarchy: dark ink for primary text, muted gray for supporting text, and maroon for deliberate emphasis. Do not use color alone to communicate status.
- Check responsive layouts at narrow widths. Cards, tables, forms, and action groups should not overflow; reduce outer padding and allow controls to wrap when needed.
- When editing global CSS, avoid broad attribute-selector overrides that unintentionally flatten borders, separators, or corner radii across unrelated controls. Prefer explicit shared component classes or targeted selectors.

## Commands

- `npm run dev` starts the Vite development server.
- `npm run build` creates the production bundle.
- `npm run preview` serves the production bundle locally.
- There is currently no test or lint script in `package.json`.

## Notes for changes

- Check route imports and links when moving or renaming page files.
- The navigation guard reads the serialized `user` value from `localStorage`; account for its current shape when changing frontend role handling.
- Do not treat client-side route role checks as a substitute for Firebase/server-side authorization.
