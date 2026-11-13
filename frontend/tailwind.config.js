// Tokens are hex values in src/index.css. Opacity modifiers (bg-accent/70) need an
// <alpha-value> slot, which Tailwind fills in; color-mix turns it into a tint of the var.
const a = (v) => `color-mix(in srgb, var(${v}) calc(<alpha-value> * 100%), transparent)`;

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      // data-terminal tokens with the Cosmic Sertão face (see .taste-skill/notes.md):
      // charcoal ground, cards darker than ground, rust as the one accent, bone text,
      // cactus green / dried blood / sand for fine / bad / watch. Values live in
      // src/index.css :root. accent is for lines, fills, focus and icons; accent-ink is
      // rust as text; positive-fill / negative-fill are bars and blocks (bone text on them).
      colors: {
        ground: a("--ground"),
        surface: a("--surface"),
        raised: a("--raised"),
        active: a("--active"),
        line: a("--border"),
        rule: a("--rule"),
        control: a("--control"),
        ink: a("--text"),
        muted: a("--muted"),
        faint: a("--faint"),
        accent: a("--accent"),
        "accent-ink": a("--accent-ink"),
        button: a("--button"),
        positive: a("--positive"),
        "positive-fill": a("--positive-fill"),
        negative: a("--negative"),
        "negative-fill": a("--negative-fill"),
        warning: a("--warning"),
      },
      fontFamily: {
        // Public Sans for text; IBM Plex Mono for every figure/ID/URL (the style's
        // decision); Alfa Slab One kept to the wordmark and display headings.
        sans: ['"Public Sans"', "Inter", "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
        display: ['"Alfa Slab One"', "Rockwell", '"Roboto Slab"', "Georgia", "serif"],
      },
      borderRadius: {
        card: "6px", // dealt radius.card
        chip: "4px",
      },
    },
  },
  plugins: [],
};
