// MathJax v4 configuration. The TeX input is rendered to SVG by the vendored
// bundle (docs/mathjax/tex-svg.js, Apache-2.0 -- see LICENSE in this directory),
// so no stylesheet or web fonts are needed.
window.MathJax = {
    tex: {
        inlineMath: [['$', '$'], ['\\(', '\\)']],
        displayMath: [['$$', '$$'], ['\\[', '\\]']],
    },
    output: {
        // Wide equations scroll inside their own box instead of overflowing the page.
        displayOverflow: 'scroll',
    },
};