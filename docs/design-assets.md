# Credimi design assets

The immutable human inputs in `HITL/` are installed unchanged at runtime:

| Input | Runtime location | SHA-256 |
| --- | --- | --- |
| `HITL/style.css` | `src/design/style.css` (`/assets/style.css`) | `ff452337f866cae1060057a8c417752b5a9767f59b748c9c7cde509c638387c7` |
| `HITL/credimi_logo.svg` | `src/design/logo/credimi_logo.svg` (`/assets/credimi_logo.svg`, `/favicon.svg`) | `031885760a9165e9d8d49eab45baca30ba5ed8dd1fbf0b4699fba2de5dc4feac` |
| `HITL/credimi_logo_negative.svg` | `src/design/logo/credimi_logo_negative.svg` (`/assets/credimi_logo_negative.svg`) | `32df33f9f5ffa696d452e1f65f5d6738b920415c5114db4b010af1f997a8cb3a` |

Use the regular logo on light surfaces and as the favicon; use the negative logo only on the dark footer. The shared stylesheet loads before the capture-specific stylesheet. Updating branding requires intentionally replacing the relevant HITL input and synchronizing its runtime copy.
