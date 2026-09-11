FONTS
=====

The TNT UI is designed around Nunito (a rounded, friendly sans-serif released under the
SIL Open Font License 1.1). The font is optional: the UI must work fully offline and must
never load anything from the internet, so it is loaded only from this folder.

Enabling Nunito
---------------

1. Download the variable font from Google Fonts (https://fonts.google.com/specimen/Nunito)
   or the upstream repository (https://github.com/googlefonts/nunito).
2. Drop the file here as exactly:

       ui/assets/fonts/Nunito-Variable.ttf

   (the file is usually named Nunito[wght].ttf or Nunito-VariableFont_wght.ttf in the
   download - rename it). Keep the licence file (OFL.txt) next to it.
3. Reload the UI. css/tnt.css declares

       @font-face { font-family: "Nunito"; src: url("../assets/fonts/Nunito-Variable.ttf") ...;
                    font-weight: 200 1000; font-display: swap; }

   and the page uses the stack
       "Nunito", "Segoe UI Variable Display", "Segoe UI", system-ui, sans-serif

If the file is missing
----------------------

Nothing breaks: the browser requests the file once, gets a 404 from the local service, and
falls through to Segoe UI Variable / Segoe UI (present on every Windows 10/11 machine).
No console error is raised for a missing @font-face source. The service build bundles the
ui/ folder without its Markdown (*.md) files, so everything else in this directory at build
time ships with the app.

Licence
-------

Nunito is copyright The Nunito Project Authors and is licensed under the SIL Open Font
License, Version 1.1 (see OFL.txt). The OFL permits bundling the font with an
application; the font itself must not be sold on its own. THIRD-PARTY-NOTICES.txt in the
TNT program folder lists the font with the other bundled components.
