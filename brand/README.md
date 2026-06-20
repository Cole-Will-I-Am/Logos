# Logos brand assets

Source brand artwork for the Logos messenger. Keep originals here; export sized
variants (favicons, iOS app-icon sets, etc.) from these as needed.

| File | What it is | Use for |
|------|------------|---------|
| `logos-wordmark.png` | Full lockup — column mark above the serif "Logos" wordmark (1254×1254, cream bg) | README headers, splash, marketing, about screen |
| `logos-wordmark-transparent.png` | Same lockup, **real transparent bg** (1254×1254, RGBA; background keyed out) | Placing the wordmark on **light** backgrounds. Note: the "Logos" text is dark ink, so it does **not** read on dark backgrounds — an inverted/light wordmark is still needed for dark UI |
| `logos-icon.png` | Column-in-circle mark (1254×1254, cream bg) | App icon, favicon, avatar, compact mark |
| `logos-emblem-book.png` | Ornate emblem — open book + sun + column on a shield (1024×1024, transparent) | Decorative / alternate badge |

## Palette (approximate)

- **Gold:** `#B0894F` (mark / accents)
- **Cream:** `#F4EFE6` (background)
- **Ink:** `#1A1714` (wordmark text)

## Notes

- `logos-emblem-book.png` is the only asset with a transparent background; the
  other two are on a cream field — crop/key out the background if a transparent
  mark is needed.
- For the iOS app icon, export square sizes from `logos-icon.png` (App Store
  needs 1024×1024 with no alpha — the cream background already satisfies that).
