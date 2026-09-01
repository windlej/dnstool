"""Monokai color theme for the dnstool TUI.

The theme is registered on the app and drives every Textual design token
(``$background``, ``$surface``, ``$panel``, ``$primary``, ``$accent``,
``$success``, ``$warning``, ``$error``, ``$text``, ``$text-muted`` and the
footer/input/cursor variables). All values are baked-in hex so the app never
falls back to the terminal's own ANSI palette.
"""

from __future__ import annotations

from textual.theme import Theme

# Monokai design tokens
MONOKAI_BG = "#272822"
MONOKAI_SURFACE = "#2e2e2e"
MONOKAI_PANEL = "#3d3c32"
MONOKAI_FG = "#f8f8f2"
MONOKAI_MUTED = "#75715e"
MONOKAI_PINK = "#f92672"
MONOKAI_YELLOW = "#e6db74"
MONOKAI_GREEN = "#a6e22e"
MONOKAI_CYAN = "#66d9ef"
MONOKAI_PURPLE = "#ae81ff"

DNSTOOL_THEME = Theme(
    name="dnstool-monokai",
    primary=MONOKAI_PINK,
    secondary=MONOKAI_PURPLE,
    accent=MONOKAI_CYAN,
    warning=MONOKAI_YELLOW,
    error=MONOKAI_PINK,
    success=MONOKAI_GREEN,
    foreground=MONOKAI_FG,
    background=MONOKAI_BG,
    surface=MONOKAI_SURFACE,
    panel=MONOKAI_PANEL,
    dark=True,
    luminosity_spread=0.15,
    variables={
        # Typography
        "text-muted": MONOKAI_MUTED,
        "foreground-muted": MONOKAI_MUTED,
        # Borders and focus rings
        "border": MONOKAI_CYAN,
        "border-blurred": MONOKAI_PANEL,
        "surface-active": "#3d3c32",
        # Cursor / selection highlight
        "block-cursor-foreground": MONOKAI_BG,
        "block-cursor-background": MONOKAI_CYAN,
        "block-cursor-text-style": "bold",
        "block-cursor-blurred-foreground": MONOKAI_FG,
        "block-cursor-blurred-background": f"{MONOKAI_CYAN} 30%",
        "block-cursor-blurred-text-style": "none",
        "block-hover-background": f"{MONOKAI_PURPLE} 15%",
        "input-cursor-foreground": MONOKAI_BG,
        "input-cursor-background": MONOKAI_CYAN,
        "input-cursor-text-style": "none",
        "input-selection-background": f"{MONOKAI_PINK} 40%",
        "input-selection-foreground": MONOKAI_FG,
        "screen-selection-background": f"{MONOKAI_PURPLE} 50%",
        "screen-selection-foreground": MONOKAI_FG,
        # Buttons
        "button-color-foreground": MONOKAI_BG,
        "button-focus-text-style": "bold",
        # Footer
        "footer-foreground": MONOKAI_FG,
        "footer-background": MONOKAI_SURFACE,
        "footer-key-foreground": MONOKAI_CYAN,
        "footer-key-background": "transparent",
        "footer-description-foreground": MONOKAI_MUTED,
        "footer-description-background": "transparent",
        "footer-item-background": "transparent",
        # Scrollbars
        "scrollbar": f"{MONOKAI_CYAN} 70%",
        "scrollbar-hover": MONOKAI_CYAN,
        "scrollbar-active": MONOKAI_PINK,
        "scrollbar-background": "#1e1f1c",
        "scrollbar-background-hover": "#1e1f1c",
        "scrollbar-background-active": "#1e1f1c",
        "scrollbar-corner-color": "#1e1f1c",
        # Links
        "link-background": "initial",
        "link-color": MONOKAI_CYAN,
        "link-color-hover": MONOKAI_PINK,
        # Command palette markdown
        "markdown-h1-color": MONOKAI_PINK,
        "markdown-h1-background": "transparent",
        "markdown-h1-text-style": "bold",
        "markdown-h2-color": MONOKAI_PURPLE,
        "markdown-h2-background": "transparent",
        "markdown-h2-text-style": "underline",
        "markdown-h3-color": MONOKAI_CYAN,
        "markdown-h3-background": "transparent",
        "markdown-h3-text-style": "none",
        "markdown-h4-color": MONOKAI_CYAN,
        "markdown-h4-background": "transparent",
        "markdown-h4-text-style": "bold",
        "markdown-h5-color": MONOKAI_YELLOW,
        "markdown-h5-background": "transparent",
        "markdown-h5-text-style": "none",
        "markdown-h6-color": MONOKAI_YELLOW,
        "markdown-h6-background": "transparent",
        "markdown-h6-text-style": "underline",
    },
)
