# Trusted Setup Video (ManimCE)

This folder contains the Manim Community Edition source code for the World ID trusted setup explainer video.

## Contents

- `trusted_setup_video.py`: scene definitions for the explainer.
- `manim.cfg`: local Manim render configuration.
- `requirements.txt`: Python dependency list for rendering.

## Canonical Renders

- Public render: [World Chain post](https://x.com/world_chain_/status/2023451971651596718?s=20)
- Local repo render (Git LFS): [`../World ID Trusted Setup.MP4`](../World%20ID%20Trusted%20Setup.MP4)

## Render Locally

Run from this directory:

```bash
manim -pql trusted_setup_video.py Scene01_Groth16Basics
manim -pqm trusted_setup_video.py Scene04_UpdatableMPC
manim -pql -a trusted_setup_video.py
```

Manim writes generated outputs under `./media/` (for example `./media/videos/trusted_setup_video/480p15/`).

## Notes

- `./media/` is generated output and is ignored by git.
- If you hit installation issues, run `manim checkhealth`.
- If your system Python is too new for Manim, use a supported version (commonly Python 3.10-3.12) in a virtual environment.
