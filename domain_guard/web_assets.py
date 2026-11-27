from pathlib import Path

STATIC = Path(__file__).resolve().parent / "static"
ASSETS = {"/": ("index.html", "text/html; charset=utf-8"),
          "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/styles.css": ("styles.css", "text/css; charset=utf-8"),
          "/Geist-Variable.woff2": ("Geist-Variable.woff2", "font/woff2"),
          "/app.mjs": ("app.mjs", "text/javascript; charset=utf-8"),
          "/input.mjs": ("input.mjs", "text/javascript; charset=utf-8"),
          "/render.mjs": ("render.mjs", "text/javascript; charset=utf-8"),
          "/demo.mjs": ("demo.mjs", "text/javascript; charset=utf-8"),
          "/report.mjs": ("report.mjs", "text/javascript; charset=utf-8"),
          "/advice.mjs": ("advice.mjs", "text/javascript; charset=utf-8"),
          "/action-plan.mjs": ("action-plan.mjs", "text/javascript; charset=utf-8"),
          "/privacy.html": ("privacy.html", "text/html; charset=utf-8"),
          "/terms.html": ("terms.html", "text/html; charset=utf-8")}
