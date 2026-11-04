// Tokens are hex values in src/index.css. Opacity modifiers (bg-accent/70) need an
// <alpha-value> slot, which Tailwind fills in; color-mix turns it into a tint of the var.
const a = (v) => `color-mix(in srgb, var(${v}) calc(<alpha-value> * 100%), transparent)`;

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      // data-terminal tokens with the abyssal face (see .taste-skill/notes.md):
      // ground tinted from the product's world (the deep), cards darker than ground,
      // phosphor teal in place of the dealt blue. Values live in src/index.css :root.
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
        positive: a("--positive"),
        negative: a("--negative"),
        warning: a("--warning"),
      },
      fontFamily: {
        // Public Sans for text; IBM Plex Mono for every figure/ID/URL (the style's
        // decision); Chakra Petch kept to the wordmark.
        sans: ['"Public Sans"', "Inter", "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
        display: ['"Chakra Petch"', '"Public Sans"', "sans-serif"],
      },
      borderRadius: {
        card: "6px", // dealt radius.card
        chip: "4px",
      },
    },
  },
  plugins: [],
};
