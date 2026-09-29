// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Render LaTeX math (`$...$` and `$$...$$`) in book pages.
// KaTeX CSS and fonts are self-hosted (katex.min.css + docs/fonts).
renderMathInElement(document.body, {
    delimiters: [
        { left: '$$', right: '$$', display: true },
        { left: '$', right: '$', display: false },
    ],
});