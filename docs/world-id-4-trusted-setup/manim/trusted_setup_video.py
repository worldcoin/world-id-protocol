"""
Trusted Setup, Explained (ManimCE)

Scenes implemented from /scenes.md.

Render examples:
  manim -pql trusted_setup_video.py Scene01_Groth16Basics
  manim -pqm trusted_setup_video.py Scene08_p0tionWorkflow
  manim -pql -a trusted_setup_video.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple

from manim import (
    AnimationGroup,
    Arrow,
    BLACK,
    BLUE,
    Circle,
    Create,
    DashedLine,
    Dot,
    DOWN,
    FadeIn,
    FadeOut,
    GREEN,
    Group,
    GrowArrow,
    Indicate,
    LaggedStart,
    LEFT,
    Line,
    ManimColor,
    NumberPlane,
    ORIGIN,
    Rectangle,
    ReplacementTransform,
    RIGHT,
    RoundedRectangle,
    Scene,
    SMALL_BUFF,
    Star,
    Succession,
    SurroundingRectangle,
    Text,
    Transform,
    TransformFromCopy,
    UR,
    UP,
    VGroup,
    Write,
    config,
    smooth,
)


@dataclass(frozen=True)
class Palette:
    bg: str = "#000000"
    text: str = "#E5E7EB"
    muted: str = "#94A3B8"
    teal: str = "#2DD4BF"
    blue: str = "#60A5FA"
    amber: str = "#F59E0B"
    red: str = "#EF4444"
    green: str = "#22C55E"


PAL = Palette()
config.background_color = PAL.bg

# Typography (macOS defaults; will fall back if unavailable).
FONT_SANS = "Avenir Next"
FONT_MONO = "Menlo"

# Timing defaults (favor slower transitions / readability).
RT_TITLE_IN = 1.8
RT_IN = 1.85
RT_BEAT = 1.6
RT_OUT = 2.4
# Global playback speed: >1.0 is faster, <1.0 is slower.
PLAYBACK_SPEED = 1.5


def _color(c: str) -> ManimColor:
    return ManimColor(c)


def txt(
    s: str,
    *,
    size: int = 28,
    color: str = PAL.text,
    font: str = FONT_SANS,
    width: float | None = None,
    height: float | None = None,
    **kwargs,
) -> Text:
    width = kwargs.pop("w", width)
    height = kwargs.pop("h", height)
    text_mobj = Text(s, font_size=size, color=_color(color), font=font, **kwargs)
    if width is not None:
        text_mobj.scale_to_fit_width(width)
    if height is not None:
        text_mobj.scale_to_fit_height(height)
    return text_mobj


def label_box(
    text: str,
    *,
    font_size: int = 24,
    color: str = PAL.blue,
    padding: float = 0.18,
    stroke_width: float = 2.25,
) -> VGroup:
    t = txt(text, size=font_size, color=PAL.text)
    box = RoundedRectangle(
        corner_radius=0.12,
        width=t.width + padding * 2,
        height=t.height + padding * 2,
        stroke_color=_color(color),
        stroke_width=stroke_width,
        fill_color=_color(PAL.bg),
        fill_opacity=0.22,
    )
    t.move_to(box.get_center())
    return VGroup(box, t)


def card(
    title: str, body: str, *, w: float = 4.0, h: float = 1.6, color: str = PAL.blue
) -> VGroup:
    r = RoundedRectangle(
        width=w,
        height=h,
        corner_radius=0.15,
        stroke_color=_color(color),
        stroke_width=2.25,
        fill_color=_color(PAL.bg),
        fill_opacity=0.14,
    )
    t_title = txt(title, size=26, color=PAL.text)
    t_body = txt(body, size=22, color=PAL.muted, line_spacing=0.9)
    content = VGroup(t_title, t_body).arrange(DOWN, buff=0.12).move_to(r.get_center())
    return VGroup(r, content)


class VerifierGate(VGroup):
    def __init__(self, label: str = "Verifier", **kwargs):
        super().__init__(**kwargs)

        frame = RoundedRectangle(
            width=3.2,
            height=4.2,
            corner_radius=0.25,
            stroke_color=_color(PAL.blue),
            stroke_width=2.5,
            fill_color=_color(PAL.bg),
            fill_opacity=0.08,
        )
        bar = Rectangle(
            width=2.6,
            height=0.18,
            fill_color=_color(PAL.blue),
            fill_opacity=0.75,
            stroke_width=0,
        ).move_to(frame.get_center())
        label_t = txt(label, size=26, color=PAL.text).next_to(frame, UP, buff=0.15)

        self.frame = frame
        self.bar = bar
        self.label = label_t
        self.add(frame, bar, label_t)


class ProofTicket(VGroup):
    def __init__(
        self,
        text: str = "Proof",
        *,
        color: str = PAL.teal,
        width: float = 2.6,
        height: float = 1.1,
        font_size: int = 28,
        **kwargs,
    ):
        super().__init__(**kwargs)
        r = RoundedRectangle(
            width=width,
            height=height,
            corner_radius=0.18,
            stroke_color=_color(color),
            stroke_width=2.5,
            fill_color=_color(PAL.bg),
            fill_opacity=0.16,
        )
        t = txt(text, size=font_size, color=PAL.text).move_to(r.get_center())
        self.rect = r
        self.text = t
        self.add(r, t)


class RoleToken(VGroup):
    def __init__(self, label: str, *, color: str = PAL.blue, **kwargs):
        super().__init__(**kwargs)
        c = RoundedRectangle(
            width=2.4,
            height=0.9,
            corner_radius=0.22,
            stroke_color=_color(color),
            stroke_width=2.25,
            fill_color=_color(PAL.bg),
            fill_opacity=0.12,
        )
        t = txt(label, size=26, color=PAL.text).move_to(c.get_center())
        self.add(c, t)


class BaseTrustedSetupScene(Scene):
    def play(self, *args, **kwargs):
        run_time = kwargs.get("run_time")
        if run_time is not None:
            kwargs["run_time"] = run_time / PLAYBACK_SPEED
        else:
            for anim in args:
                if hasattr(anim, "run_time") and anim.run_time is not None:
                    anim.run_time = anim.run_time / PLAYBACK_SPEED
        return super().play(*args, **kwargs)

    def wait(self, duration=1.0, stop_condition=None):
        if duration is None:
            return super().wait(duration=duration, stop_condition=stop_condition)
        return super().wait(
            duration=duration / PLAYBACK_SPEED, stop_condition=stop_condition
        )

    def setup(self):
        self.camera.background_color = PAL.bg
        grid = NumberPlane(
            background_line_style={
                "stroke_color": _color("#FFFFFF"),
                "stroke_width": 1.0,
                "stroke_opacity": 0.11,
            },
            axis_config={
                "stroke_opacity": 0.0,
            },
            faded_line_ratio=4,
        )
        self._bg = VGroup(grid)
        self.add(self._bg)

    def scene_title(
        self,
        title: str,
        *,
        subtitle: str | None = None,
        corner: str | None = None,
        corner_color: str = PAL.blue,
    ) -> Tuple[VGroup, VGroup | None]:
        t = txt(title, size=54, color=PAL.text)
        s = None
        if subtitle:
            s = txt(subtitle, size=28, color=PAL.muted)
            VGroup(t, s).arrange(DOWN, buff=0.18).to_edge(UP)
        else:
            t.to_edge(UP)
        corner_box = None
        if corner:
            corner_box = label_box(corner, font_size=22, color=corner_color).to_corner(
                UR, buff=0.25
            )
        group = VGroup(t, s) if s else VGroup(t)
        return (group, corner_box)

    def transition_out(self, *mobjects, run_time: float = RT_OUT):
        grp = VGroup(*[m for m in mobjects if m is not None])
        if len(grp) == 0:
            return
        self.play(FadeOut(grp, shift=DOWN * 0.08), run_time=run_time)

    def play_and_pause(self, *anims, post_wait: float = 1.8, **kwargs):
        self.play(*anims, **kwargs)
        self.wait(post_wait)


# --------------------------------------------------------------------
# Scene 1
# --------------------------------------------------------------------


class Scene01_Groth16Basics(BaseTrustedSetupScene):
    def construct(self):
        title, teaser = self.scene_title(
            "Zero-Knowledge Proofs",
            subtitle="Convince someone, without revealing your secret",
            corner="Case Study Later: World ID 4.0 + p0tion",
            corner_color=PAL.teal,
        )
        teaser.scale(1.2).center().shift(DOWN)
        self.play_and_pause(FadeIn(title, shift=DOWN * 0.05), run_time=RT_TITLE_IN)
        self.play_and_pause(FadeIn(teaser, shift=DOWN * 0.12), run_time=RT_BEAT)
        self.wait(0.5)
        self.play_and_pause(FadeOut(teaser, shift=UP * 0.06), run_time=RT_BEAT)
        self.wait(0.25)

        statement = card(
            "Statement (public)",
            "“I know a password\nthat unlocks this box.”",
            color=PAL.blue,
            w=5.5,
            h=1.9,
        ).move_to(UP * 0.95)
        self.play_and_pause(FadeIn(statement, shift=UP * 0.08), run_time=RT_IN)
        self.wait(0.25)

        prover = RoleToken("Prover", color=PAL.blue).move_to(LEFT * 4.2 + DOWN * 1.45)
        verifier = RoleToken("Verifier", color=PAL.blue).move_to(
            RIGHT * 4.2 + DOWN * 1.45
        )
        channel = Arrow(
            prover.get_right() + RIGHT * 0.08,
            verifier.get_left() + LEFT * 0.08,
            buff=0.15,
            stroke_width=2.6,
            color=_color(PAL.muted),
        ).set_opacity(0.45)
        secret = label_box("Password (secret)", font_size=24, color=PAL.amber).next_to(
            prover, DOWN, buff=0.45
        )
        self.play_and_pause(
            FadeIn(prover, shift=RIGHT * 0.1),
            FadeIn(verifier, shift=LEFT * 0.1),
            GrowArrow(channel),
            FadeIn(secret, shift=UP * 0.08),
            run_time=RT_IN,
        )
        self.wait(0.25)

        caption = txt(
            "Verifier accepts, but never sees the password.", size=19, color=PAL.muted
        ).to_edge(DOWN, buff=0.62)
        self.play_and_pause(
            secret.animate.set_opacity(0.18),
            FadeIn(caption, shift=UP * 0.05),
            run_time=RT_BEAT,
        )
        self.wait(0.6)
        self.play_and_pause(FadeOut(caption, shift=DOWN * 0.06), run_time=RT_BEAT)
        self.wait(0.2)

        proof = (
            ProofTicket("Proof", color=PAL.teal)
            .scale(0.88)
            .move_to(LEFT * 1.75 + DOWN * 0.9)
        )
        self.play_and_pause(TransformFromCopy(statement, proof), run_time=RT_BEAT)
        self.wait(0.2)
        self.play_and_pause(
            proof.animate.move_to(RIGHT * 1.35 + DOWN * 0.9),
            run_time=RT_BEAT,
        )

        accept = label_box("ACCEPT", font_size=26, color=PAL.green).next_to(
            verifier, UP, buff=0.45
        )
        self.play_and_pause(FadeIn(accept, shift=DOWN * 0.08), run_time=RT_BEAT)
        self.wait(0.5)

        phase_demo = VGroup(statement, secret, proof, accept, prover, verifier, channel)
        self.play_and_pause(FadeOut(phase_demo, shift=DOWN * 0.06), run_time=RT_OUT)
        self.wait(0.25)

        d_statement = label_box(
            "Statement: what you claim", font_size=22, color=PAL.blue
        )
        d_witness = label_box("Witness: the secret", font_size=22, color=PAL.amber)
        d_proof = label_box(
            "Proof: convinces without revealing", font_size=22, color=PAL.teal
        )
        defs = (
            VGroup(d_statement, d_witness, d_proof)
            .arrange(DOWN, buff=0.22)
            .move_to(DOWN * 0.35)
        )

        self.play_and_pause(FadeIn(d_statement, shift=UP * 0.05), run_time=RT_IN)
        self.play_and_pause(FadeIn(d_witness, shift=UP * 0.05), run_time=RT_IN)
        self.play_and_pause(FadeIn(d_proof, shift=UP * 0.05), run_time=RT_IN)
        self.wait(0.6)

        self.play_and_pause(FadeOut(defs, shift=DOWN * 0.06), run_time=RT_OUT)
        self.wait(0.25)

        setup = label_box(
            "Some proof systems need a one-time setup.", font_size=26, color=PAL.teal
        )
        setup.move_to(DOWN * 0.25)
        self.play_and_pause(FadeIn(setup, shift=DOWN * 0.08), run_time=RT_IN)
        self.wait(5)

        self.transition_out(title, setup)


# --------------------------------------------------------------------
# Scene 2
# --------------------------------------------------------------------


class Scene02_CRSArtifacts(BaseTrustedSetupScene):
    def construct(self):
        title, _ = self.scene_title(
            "Trusted setup outputs",
            subtitle="Public setup parameters used to make + verify proofs",
        )
        self.play(FadeIn(title, shift=DOWN * 0.05), run_time=RT_TITLE_IN)
        self.wait(0.35)

        crs = RoundedRectangle(
            width=8.9,
            height=3.9,
            corner_radius=0.25,
            stroke_color=_color(PAL.blue),
            stroke_width=2.5,
            fill_color=_color(PAL.bg),
            fill_opacity=0.08,
        ).shift(DOWN * 0.62)
        crs_label = txt("Setup parameters (public)", size=28, color=PAL.text).next_to(
            crs, UP, buff=0.12
        )

        split = Line(crs.get_top() + DOWN * 0.22, crs.get_bottom() + UP * 0.22).move_to(
            crs.get_center()
        )
        split.set_color(_color(PAL.muted)).set_stroke(width=2, opacity=0.5)

        pk_box = RoundedRectangle(
            width=3.55,
            height=2.25,
            corner_radius=0.2,
            stroke_color=_color(PAL.teal),
            stroke_width=2.25,
            fill_color=_color(PAL.bg),
            fill_opacity=0.0,
        ).move_to(crs.get_center() + LEFT * 2.05 + UP * 0.1)
        vk_box = (
            pk_box.copy()
            .set_stroke(color=_color(PAL.blue))
            .move_to(crs.get_center() + RIGHT * 2.05 + UP * 0.1)
        )

        pk = txt("Proving Key", size=30, color=PAL.teal).move_to(pk_box.get_center())
        vk = txt("Verifying Key", size=30, color=PAL.blue).move_to(vk_box.get_center())
        pk_note = label_box("Used by the prover", font_size=22, color=PAL.teal).next_to(
            pk_box, DOWN, buff=0.24
        )
        vk_note = label_box(
            "Used by the verifier", font_size=22, color=PAL.blue
        ).next_to(vk_box, DOWN, buff=0.24)

        self.play(Create(crs), FadeIn(crs_label, shift=UP * 0.05), run_time=RT_IN)
        self.play(Create(split), run_time=RT_BEAT)
        self.play(Create(pk_box), Create(vk_box), run_time=RT_IN)
        self.play(
            FadeIn(pk, shift=UP * 0.04), FadeIn(vk, shift=UP * 0.04), run_time=RT_IN
        )
        self.play(
            FadeIn(pk_note, shift=UP * 0.05),
            FadeIn(vk_note, shift=UP * 0.05),
            run_time=RT_IN,
        )

        note = txt(
            "These files are published for everyone.", size=23, color=PAL.muted
        ).to_edge(DOWN, buff=0.42)
        self.play(FadeIn(note, shift=UP * 0.05), run_time=RT_IN)
        self.wait(5)

        self.transition_out(
            title, crs, crs_label, split, pk_box, vk_box, pk, vk, pk_note, vk_note, note
        )


# --------------------------------------------------------------------
# Scene 3
# --------------------------------------------------------------------


class Scene03_ToxicWaste(BaseTrustedSetupScene):
    def construct(self):
        title, _ = self.scene_title(
            "Toxic waste (the danger)",
            subtitle="A hidden setup secret that enables fake proofs",
        )
        self.play(FadeIn(title, shift=DOWN * 0.05), run_time=RT_TITLE_IN)
        self.wait(0.35)

        vial = RoundedRectangle(
            width=2.3,
            height=3.1,
            corner_radius=0.3,
            stroke_color=_color(PAL.red),
            stroke_width=2.5,
            fill_color=_color(PAL.red),
            fill_opacity=0.10,
        ).shift(LEFT * 4.15 + DOWN * 0.25)
        vial_lbl = txt(
            "Setup\nsecret", size=28, color=PAL.red, line_spacing=0.85
        ).move_to(vial.get_center())
        vial_hint = txt("(must be destroyed)", size=22, color=PAL.muted).next_to(
            vial, DOWN, buff=0.2
        )

        safe = label_box("If destroyed", font_size=24, color=PAL.green).shift(
            RIGHT * 1 + UP * 1.1
        )
        bad = label_box("If kept", font_size=24, color=PAL.red).shift(
            RIGHT * 1 + DOWN * 0.15
        )

        self.play(
            Create(vial),
            Write(vial_lbl),
            FadeIn(vial_hint, shift=UP * 0.05),
            run_time=RT_IN,
        )
        self.play(
            FadeIn(safe, shift=DOWN * 0.12),
            FadeIn(bad, shift=UP * 0.12),
            run_time=RT_IN,
        )

        honest = (
            ProofTicket(
                "Proof is unspoofable",
                color=PAL.green,
                width=3.9,
                height=1.0,
                font_size=24,
            )
            .scale(0.9)
            .next_to(safe, RIGHT, buff=0.92)
        )
        forged = (
            ProofTicket(
                "Proof can be forged",
                color=PAL.red,
                width=3.9,
                height=1.0,
                font_size=24,
            )
            .scale(0.9)
            .next_to(bad, RIGHT, buff=0.92)
        )

        self.play(FadeIn(honest, shift=LEFT * 0.12), run_time=RT_IN)
        self.play(FadeIn(forged, shift=LEFT * 0.12), run_time=RT_IN)

        same = txt(
            "They can look identical to the verifier.", size=23, color=PAL.muted
        ).to_edge(DOWN, buff=0.48)
        self.play(FadeIn(same, shift=UP * 0.05), run_time=RT_IN)
        self.wait(5)

        branch = VGroup(safe, bad, honest, forged, same)
        self.play(FadeOut(branch, shift=DOWN * 0.05), run_time=RT_BEAT)

        n0 = txt("What this means", size=28, color=PAL.text)
        privacy_note = txt("Privacy still holds.", size=28, color=PAL.text)
        forgery_note = txt(
            "Risk: forged proofs if setup secret survives.", size=28, color=PAL.red
        )
        notes = (
            VGroup(n0, privacy_note, forgery_note)
            .arrange(DOWN, aligned_edge=LEFT, buff=0.2)
            .move_to(RIGHT * 1.9 + DOWN * 0.05)
        )
        box = SurroundingRectangle(
            notes, color=_color(PAL.blue), buff=0.28, corner_radius=0.15
        )
        self.play(
            FadeIn(box, shift=UP * 0.05), FadeIn(notes, shift=UP * 0.05), run_time=RT_IN
        )
        self.wait(5)

        self.transition_out(title, vial, vial_lbl, vial_hint, box, notes)


# --------------------------------------------------------------------
# Scene 4
# --------------------------------------------------------------------


class Scene04_UpdatableMPC(BaseTrustedSetupScene):
    def construct(self):
        title, _ = self.scene_title(
            "Many contributors (the core trick)",
            subtitle="If one person is honest, we're safe.",
        )
        self.play(Write(title), run_time=RT_TITLE_IN)
        self.wait(0.35)

        contributors: list[VGroup] = []
        for i in range(1, 4):
            c = RoleToken(f"C{i}", color=PAL.amber).scale(0.86)
            c.shift(LEFT * 3.1 + RIGHT * (i - 1) * 3.1 + DOWN * 0.2)
            contributors.append(c)

        connector_01 = Arrow(
            contributors[0].get_right() + RIGHT * 0.03,
            contributors[1].get_left() + LEFT * 0.03,
            buff=0.16,
            stroke_width=2.6,
            color=_color(PAL.muted),
        ).set_opacity(0.55)
        connector_12 = Arrow(
            contributors[1].get_right() + RIGHT * 0.03,
            contributors[2].get_left() + LEFT * 0.03,
            buff=0.16,
            stroke_width=2.6,
            color=_color(PAL.muted),
        ).set_opacity(0.55)
        inbound = Arrow(
            LEFT * 5.8 + DOWN * 0.2,
            contributors[0].get_left() + LEFT * 0.05,
            buff=0.15,
            stroke_width=2.4,
            color=_color(PAL.muted),
        ).set_opacity(0.55)

        param = Dot(color=_color(PAL.blue), radius=0.12).move_to(inbound.get_start())
        state = (
            label_box("Parameter state: P0", font_size=22, color=PAL.blue)
            .to_edge(DOWN)
            .shift(UP * 0.5)
        )

        self.play(
            LaggedStart(
                *[FadeIn(c, shift=UP * 0.08) for c in contributors], lag_ratio=0.12
            ),
            Create(inbound),
            Create(connector_01),
            Create(connector_12),
            FadeIn(param, shift=UP * 0.03),
            FadeIn(state, shift=UP * 0.03),
            run_time=RT_IN,
        )

        for i, c in enumerate(contributors, start=1):
            r_txt = txt(f"secret r{i}", size=24, color=PAL.amber).next_to(
                c, UP, buff=0.18
            )
            destroy_tag = label_box("destroyed", font_size=18, color=PAL.red).next_to(
                c, DOWN, buff=0.2
            )
            incoming_pos = c.get_left() + RIGHT * 0.24
            outgoing_pos = c.get_right() + LEFT * 0.24
            next_state = label_box(
                f"Parameter state: P{i}", font_size=22, color=PAL.blue
            ).move_to(state)

            self.play(
                param.animate.move_to(incoming_pos),
                FadeIn(r_txt, shift=DOWN * 0.05),
                run_time=RT_BEAT,
            )
            self.play(param.animate.move_to(outgoing_pos), run_time=RT_BEAT)
            self.play(ReplacementTransform(state, next_state), run_time=RT_BEAT)
            state = next_state
            self.play(FadeIn(destroy_tag, shift=UP * 0.03), run_time=RT_BEAT * 0.7)
            self.play(FadeOut(r_txt, shift=DOWN * 0.05), run_time=RT_BEAT * 0.7)
            self.play(FadeOut(destroy_tag, shift=DOWN * 0.03), run_time=RT_BEAT * 0.7)
            self.wait(0.15)

        self.play(FadeOut(state, shift=DOWN * 0.04), run_time=RT_BEAT)

        conclusion = txt(
            "If at least one contributor destroys their secret,\n"
            "no one can reconstruct the trapdoor\n"
            "that can be used to spoof proofs and fool the verifier.",
            size=27,
            color=PAL.text,
            line_spacing=0.9,
        ).to_edge(DOWN, buff=0.42)
        concl_box = SurroundingRectangle(
            conclusion, color=_color(PAL.teal), buff=0.25, corner_radius=0.15
        )
        self.play(FadeIn(concl_box), Write(conclusion), run_time=RT_IN)
        self.wait(5)

        self.transition_out(
            title,
            *contributors,
            inbound,
            connector_01,
            connector_12,
            param,
            conclusion,
            concl_box,
        )


# --------------------------------------------------------------------
# Scene 5
# --------------------------------------------------------------------


def transcript_block(label: str, inp: str, out: str) -> VGroup:
    box = RoundedRectangle(
        width=3.1,
        height=1.8,
        corner_radius=0.2,
        stroke_color=_color(PAL.blue),
        stroke_width=2.25,
        fill_color=_color(PAL.bg),
        fill_opacity=0.10,
    )
    t0 = txt(label, size=26, color=PAL.text)
    t1 = txt(f"in:  {inp}", size=20, color=PAL.muted, font=FONT_MONO)
    t2 = txt(f"out: {out}", size=20, color=PAL.muted, font=FONT_MONO)
    g = VGroup(t0, t1, t2).arrange(DOWN, buff=0.12).move_to(box.get_center())
    return VGroup(box, g)


class Scene05_TranscriptChain(BaseTrustedSetupScene):
    def construct(self):
        title, _ = self.scene_title(
            "Publicly verifiable",
            subtitle="Transcript chain + checks (without revealing secrets)",
        )
        self.play(Write(title), run_time=RT_TITLE_IN)
        self.wait(0.35)

        blocks = [
            transcript_block("T0", "a3f9...", "c1d2..."),
            transcript_block("T1", "c1d2...", "7b8e..."),
            transcript_block("T2", "7b8e...", "0f12..."),
        ]
        chain = VGroup(*blocks).arrange(RIGHT, buff=0.7).shift(DOWN * 0.5)

        arrows = VGroup(
            Arrow(
                chain[0].get_right(),
                chain[1].get_left(),
                buff=0.15,
                stroke_width=2.75,
                color=_color(PAL.muted),
            ),
            Arrow(
                chain[1].get_right(),
                chain[2].get_left(),
                buff=0.15,
                stroke_width=2.75,
                color=_color(PAL.muted),
            ),
        )

        self.play(
            LaggedStart(*[Create(b) for b in chain], lag_ratio=0.15), run_time=RT_IN
        )
        self.play(
            LaggedStart(*[GrowArrow(a) for a in arrows], lag_ratio=0.2),
            run_time=RT_BEAT,
        )

        check = label_box(
            "Anyone can verify the chain links + proofs check out",
            font_size=24,
            color=PAL.teal,
        ).to_edge(DOWN)
        self.play(FadeIn(check, shift=UP * 0.12), run_time=RT_IN)
        self.wait(5)
        self.transition_out(title, chain, arrows, check)


# --------------------------------------------------------------------
# Scene 6
# --------------------------------------------------------------------


class Scene06_Phase1Phase2Pipeline(BaseTrustedSetupScene):
    def construct(self):
        title, _ = self.scene_title(
            "Two phases of setup",
            subtitle="Universal setup, then circuit-specific setup",
        )
        self.play(Write(title), run_time=RT_TITLE_IN)
        self.wait(0.35)

        phase1 = label_box("Phase 1 (universal)", color=PAL.blue, font_size=26)
        ptau = label_box(".ptau", color=PAL.blue, font_size=26)
        circuit = label_box("Circuit (R1CS)", color=PAL.amber, font_size=26)
        phase2 = label_box("Phase 2 (per circuit)", color=PAL.teal, font_size=26)
        zkey = label_box(".zkey", color=PAL.teal, font_size=26)

        row1 = VGroup(phase1, ptau).arrange(RIGHT, buff=0.8)
        row2 = VGroup(circuit, phase2, zkey).arrange(RIGHT, buff=0.8)
        diagram = VGroup(row1, row2).arrange(DOWN, buff=0.8).shift(DOWN * 0.2)

        a1 = Arrow(
            phase1.get_right(),
            ptau.get_left(),
            buff=0.15,
            stroke_width=2.75,
            color=_color(PAL.muted),
        )
        a2 = Arrow(
            circuit.get_right(),
            phase2.get_left(),
            buff=0.15,
            stroke_width=2.75,
            color=_color(PAL.muted),
        )
        a3 = Arrow(
            phase2.get_right(),
            zkey.get_left(),
            buff=0.15,
            stroke_width=2.75,
            color=_color(PAL.muted),
        )
        cross = DashedLine(
            ptau.get_bottom(), phase2.get_top(), stroke_width=2, color=_color(PAL.muted)
        ).set_opacity(0.6)
        cross_lbl = txt(
            "Phase 2 uses Phase 1 output", size=22, color=PAL.muted
        ).next_to(cross, RIGHT, buff=0.2)

        self.play(FadeIn(diagram, shift=UP * 0.1), run_time=RT_IN)
        self.play(
            LaggedStart(GrowArrow(a1), GrowArrow(a2), GrowArrow(a3), lag_ratio=0.15),
            run_time=RT_BEAT,
        )
        self.play(Create(cross), FadeIn(cross_lbl, shift=LEFT * 0.08), run_time=RT_BEAT)
        self.wait(5)
        self.transition_out(title, diagram, a1, a2, a3, cross, cross_lbl)


# --------------------------------------------------------------------
# Scene 7
# --------------------------------------------------------------------


class Scene07_WorldIDPivot(BaseTrustedSetupScene):
    def construct(self):
        title, _ = self.scene_title(
            "World ID 4.0 (case study)",
            subtitle="Multiple Groth16 circuits, each needs Phase 2 parameters",
        )
        self.play(Write(title), run_time=RT_TITLE_IN)
        self.wait(0.35)

        stack_title = txt("OPRF-service circuits", size=28, color=PAL.text)
        circuits = [
            label_box("OPRFQueryProof", font_size=21, color=PAL.blue),
            label_box("OPRFNullifierProof", font_size=21, color=PAL.blue),
            label_box("OPRFKeyGenProof13", font_size=21, color=PAL.blue),
            label_box("OPRFKeyGenProof25", font_size=21, color=PAL.blue),
            label_box("OPRFKeyGenProof37", font_size=21, color=PAL.blue),
        ]
        stack = VGroup(*circuits).arrange(DOWN, buff=0.2)
        stack_group = VGroup(stack_title, stack).arrange(DOWN, buff=0.28)

        icons = VGroup(
            label_box("R1CS", font_size=22, color=PAL.amber),
            label_box("WASM", font_size=22, color=PAL.amber),
        ).arrange(RIGHT, buff=0.2)

        anchor = VGroup(
            label_box("Repro anchor", font_size=24, color=PAL.teal),
            txt(
                "source commit + circom version + sha256",
                size=20,
                color=PAL.muted,
                width=5.2,
            ),
        ).arrange(DOWN, aligned_edge=LEFT, buff=0.24)

        right_group = VGroup(anchor, icons).arrange(DOWN, aligned_edge=LEFT, buff=0.5)
        body = VGroup(stack_group, right_group).arrange(
            RIGHT, aligned_edge=UP, buff=0.9
        )
        subtitle_gap = 0.78
        bottom_margin = 0.45
        available_h = (
            title.get_bottom()[1]
            - (-config.frame_height / 2 + bottom_margin)
            - subtitle_gap
        )
        if body.height > available_h:
            body.scale_to_fit_height(available_h)
        max_body_width = config.frame_width - 0.8
        if body.width > max_body_width:
            body.scale_to_fit_width(max_body_width)
        body.next_to(title, DOWN, buff=subtitle_gap)

        self.play(FadeIn(stack_group, shift=UP * 0.1), run_time=RT_IN)
        self.play(FadeIn(icons, shift=LEFT * 0.08), run_time=RT_IN)
        self.play(FadeIn(anchor, shift=LEFT * 0.08), run_time=RT_IN)
        self.wait(5)

        self.transition_out(title, stack_group, icons, anchor)


# --------------------------------------------------------------------
# Scene 8
# --------------------------------------------------------------------


class Scene08_p0tionPrimer(BaseTrustedSetupScene):
    def construct(self):
        title, _ = self.scene_title(
            "What is p0tion?",
            subtitle="PSE's tooling for large, auditable Groth16 ceremonies",
        )
        self.play(FadeIn(title, shift=DOWN * 0.05), run_time=RT_TITLE_IN)
        self.wait(2.5)

        col_w = 4.15
        col_h = 2.85

        def primer_column(head: str, body: str, color: str) -> VGroup:
            # Invisible layout box to enforce fixed-width columns and prevent overlap.
            slot = Rectangle(
                width=col_w, height=col_h, stroke_opacity=0, fill_opacity=0
            )
            header = label_box(head, font_size=24, color=color)
            header.scale_to_fit_width(col_w - 0.25)
            header.move_to(slot.get_top() + DOWN * 0.45)

            details = txt(
                body,
                size=20,
                color=PAL.muted,
                line_spacing=0.9,
            )
            if details.width > col_w - 0.3:
                details.scale_to_fit_width(col_w - 0.3)
            details.next_to(header, DOWN, buff=0.22)
            details.align_to(slot, LEFT).shift(RIGHT * 0.1)

            return VGroup(slot, header, details)

        who = primer_column(
            "Who built it: PSE",
            "Privacy Stewards of Ethereum\n(Ethereum ecosystem R&D)",
            PAL.blue,
        )
        why = primer_column(
            "Why they built it",
            "To coordinate many contributors,\nreduce ceremony mistakes,\nand keep everything auditable.",
            PAL.teal,
        )
        how = primer_column(
            "How p0tion works",
            "Queue circuits -> contribute entropy\n-> verify transcript\n-> finalize artifacts.",
            PAL.amber,
        )
        columns = (
            VGroup(who, why, how)
            .arrange(RIGHT, buff=0.35, aligned_edge=UP)
            .move_to(DOWN * 0.28)
        )
        max_columns_width = config.frame_width - 0.7
        if columns.width > max_columns_width:
            columns.scale_to_fit_width(max_columns_width)

        flow = (
            VGroup(
                label_box("Coordinator", font_size=18, color=PAL.teal),
                label_box("Participants", font_size=18, color=PAL.blue),
                label_box("Observers", font_size=18, color=PAL.muted),
            )
            .arrange(RIGHT, buff=0.28)
            .to_edge(DOWN, buff=0.72)
        )
        max_flow_width = config.frame_width - 1.5
        if flow.width > max_flow_width:
            flow.scale_to_fit_width(max_flow_width)

        self.play(FadeIn(who, shift=UP * 0.07), run_time=RT_IN)
        self.play(FadeIn(why, shift=UP * 0.07), run_time=RT_IN)
        self.play(FadeIn(how, shift=UP * 0.07), run_time=RT_IN)
        self.play(FadeIn(flow, shift=UP * 0.06), run_time=RT_IN)
        self.wait(5)

        self.transition_out(title, columns, flow)


class Scene08_p0tionWorkflow(BaseTrustedSetupScene):
    def construct(self):
        title, _ = self.scene_title(
            "Ceremony workflow (p0tion-style)",
            subtitle="Coordinator + participants + observers",
        )
        self.play(FadeIn(title, shift=DOWN * 0.05), run_time=RT_TITLE_IN)
        self.wait(0.35)

        roles = (
            VGroup(
                RoleToken("Coordinator", color=PAL.teal),
                RoleToken("Participants", color=PAL.blue),
                RoleToken("Observers", color=PAL.muted),
            )
            .arrange(RIGHT, buff=0.52)
            .shift(UP * 1.66)
        )

        queue = (
            VGroup(
                label_box("Circuit 1 queue", font_size=22, color=PAL.blue),
                label_box("Circuit 2 queue", font_size=22, color=PAL.blue),
                label_box("Circuit 3 queue", font_size=22, color=PAL.blue),
            )
            .arrange(DOWN, buff=0.22)
            .shift(LEFT * 4.45 + DOWN * 0.88)
        )

        steps = (
            VGroup(
                txt("1) auth", size=20, color=PAL.text),
                txt("2) wait in queue", size=20, color=PAL.text),
                txt("3) download latest", size=20, color=PAL.text),
                txt("4) contribute entropy", size=20, color=PAL.text),
                txt("5) upload", size=20, color=PAL.text),
                txt("6) verify + attest", size=20, color=PAL.text),
            )
            .arrange(DOWN, aligned_edge=LEFT, buff=0.14)
            .shift(RIGHT * 2.65 + DOWN * 0.9)
        )
        steps_box = SurroundingRectangle(
            steps, color=_color(PAL.blue), buff=0.34, corner_radius=0.15
        )

        cli = (
            VGroup(
                txt(
                    "world-id-trusted-setup-cli auth",
                    size=20,
                    color=PAL.muted,
                    font=FONT_MONO,
                ),
                txt(
                    "world-id-trusted-setup-cli contribute",
                    size=20,
                    color=PAL.muted,
                    font=FONT_MONO,
                ),
                txt(
                    "world-id-trusted-setup-cli coordinate setup | observe | finalize",
                    size=20,
                    color=PAL.muted,
                    font=FONT_MONO,
                ),
            )
            .arrange(DOWN, aligned_edge=LEFT, buff=0.11)
            .to_edge(DOWN, buff=0.22)
        )

        self.play(FadeIn(roles, shift=DOWN * 0.08), run_time=RT_IN)
        self.play(FadeIn(queue, shift=RIGHT * 0.08), run_time=RT_IN)
        self.play(
            FadeIn(steps_box, shift=UP * 0.04),
            FadeIn(steps, shift=UP * 0.06),
            run_time=RT_IN,
        )
        self.play(FadeIn(cli, shift=UP * 0.08), run_time=RT_IN)
        self.wait(5)
        self.transition_out(title, roles, queue, steps_box, steps, cli)


# --------------------------------------------------------------------
# Scene 9
# --------------------------------------------------------------------


class Scene09_FinalizationArtifacts(BaseTrustedSetupScene):
    def construct(self):
        title, _ = self.scene_title(
            "Finalization",
            subtitle="Lock transcript with public randomness, then derive final artifacts",
        )
        self.play(Write(title), run_time=RT_TITLE_IN)
        self.wait(0.35)

        transcript = label_box("Final transcript state", font_size=22, color=PAL.blue)
        transcript.scale_to_fit_width(4.4)

        beacon = label_box("Public random beacon hash", font_size=21, color=PAL.amber)
        beacon.scale_to_fit_width(4.4)
        left_stack = VGroup(transcript, beacon).arrange(
            DOWN, buff=0.56, aligned_edge=LEFT
        )

        shelf = RoundedRectangle(
            width=5.35,
            height=3.35,
            corner_radius=0.25,
            stroke_color=_color(PAL.teal),
            stroke_width=2.25,
            fill_color=_color(PAL.bg),
            fill_opacity=0.08,
        )

        items = VGroup(
            label_box("final.zkey", font_size=20, color=PAL.teal),
            label_box("verification_key.json", font_size=19, color=PAL.blue),
            label_box("verifier.sol", font_size=20, color=PAL.blue),
        )
        max_item_width = shelf.width - 0.75
        for item in items:
            if item.width > max_item_width:
                item.scale_to_fit_width(max_item_width)
        items.arrange(DOWN, buff=0.3)
        max_items_h = shelf.height - 0.85
        if items.height > max_items_h:
            items.scale_to_fit_height(max_items_h)
        items.move_to(shelf.get_center() + DOWN * 0.02)
        shelf_label = txt("Deterministic outputs", size=20, color=PAL.muted).next_to(
            shelf, UP, buff=0.18
        )
        outputs_group = VGroup(shelf, shelf_label, items)

        body = VGroup(left_stack, outputs_group).arrange(
            RIGHT, buff=1.1, aligned_edge=UP
        )
        subtitle_gap = 0.78
        bottom_margin = 1.18
        available_h = (
            title.get_bottom()[1]
            - (-config.frame_height / 2 + bottom_margin)
            - subtitle_gap
        )
        if body.height > available_h:
            body.scale_to_fit_height(available_h)
        max_body_width = config.frame_width - 0.8
        if body.width > max_body_width:
            body.scale_to_fit_width(max_body_width)
        body.next_to(title, DOWN, buff=subtitle_gap)

        a1 = Arrow(
            transcript.get_bottom(),
            beacon.get_top(),
            buff=0.15,
            stroke_width=2.5,
            color=_color(PAL.muted),
        ).set_opacity(0.6)

        a2 = Arrow(
            beacon.get_right(),
            shelf.get_left(),
            buff=0.15,
            stroke_width=2.5,
            color=_color(PAL.muted),
        ).set_opacity(0.6)

        self.play(FadeIn(transcript, shift=UP * 0.08), run_time=RT_IN)
        self.play(FadeIn(beacon, shift=UP * 0.08), GrowArrow(a1), run_time=RT_IN)
        self.play(
            Create(shelf),
            GrowArrow(a2),
            FadeIn(items, shift=UP * 0.08),
            FadeIn(shelf_label, shift=UP * 0.04),
            run_time=RT_IN,
        )

        stamp = (
            label_box("FINALIZED", font_size=26, color=PAL.green)
            .scale(0.76)
            .rotate(0.08)
            .move_to(shelf.get_corner(UR) + LEFT * 0.54 + UP * 0.28)
        )
        beacon_hash = txt(
            "Beacon randomness prevents precomputed trapdoors and keeps finalization auditable.",
            size=18,
            color=PAL.muted,
            width=config.frame_width - 1.1,
        ).to_edge(DOWN, buff=0.22)
        self.play(Write(stamp), run_time=RT_BEAT)
        self.play(FadeIn(beacon_hash, shift=UP * 0.04), run_time=RT_IN)
        self.wait(5)

        self.transition_out(
            title,
            transcript,
            beacon,
            a1,
            a2,
            shelf,
            shelf_label,
            items,
            stamp,
            beacon_hash,
        )


# --------------------------------------------------------------------
# Scene 10
# --------------------------------------------------------------------


class Scene10_AuditChecklist(BaseTrustedSetupScene):
    def construct(self):
        title, _ = self.scene_title(
            "What to trust", subtitle="A practical audit checklist"
        )
        self.play(Write(title), run_time=RT_TITLE_IN)
        self.wait(0.35)

        items = [
            "Verify transcript chain end-to-end",
            "Inputs reproducible (commit + compiler + hashes)",
            "Contribution hashes match",
            "Beacon hash published",
            "Final artifacts derived from final transcript",
            "At least one honest entropy contribution",
        ]

        rows = VGroup()
        for s in items:
            box = Rectangle(
                width=0.35, height=0.35, stroke_color=_color(PAL.muted), stroke_width=2
            )
            t = txt(s, size=26, color=PAL.text)
            row = VGroup(box, t).arrange(RIGHT, buff=0.3)
            rows.add(row)
        rows.arrange(DOWN, aligned_edge=LEFT, buff=0.22).shift(DOWN * 0.3)

        self.play(
            LaggedStart(*[FadeIn(r, shift=UP * 0.05) for r in rows], lag_ratio=0.08),
            run_time=RT_IN,
        )

        checks = VGroup()
        for r in rows:
            check = txt("OK", size=20, color=PAL.green, font=FONT_MONO).move_to(
                r[0].get_center()
            )
            self.play(FadeIn(check, shift=UP * 0.03), run_time=0.55)
            checks.add(check)
            self.wait(0.18)

        self.wait(5)
        self.transition_out(title, rows, checks)


# --------------------------------------------------------------------
# Scene 11
# --------------------------------------------------------------------


class Scene11_AlternativesTradeoffs(BaseTrustedSetupScene):
    def construct(self):
        title, _ = self.scene_title(
            "Alternatives and tradeoffs", subtitle="Why people still use Groth16"
        )
        self.play(FadeIn(title, shift=DOWN * 0.05), run_time=RT_TITLE_IN)
        self.wait(0.35)

        toxic_ref = txt(
            "Reminder: toxic waste = hidden setup trapdoor that could spoof proofs.",
            size=21,
            color=PAL.muted,
        ).shift(UP * 1.62)
        headers = (
            VGroup(
                label_box("Groth16", font_size=26, color=PAL.teal),
                label_box("Universal-setup SNARKs", font_size=26, color=PAL.blue),
                label_box("STARKs", font_size=26, color=PAL.amber),
            )
            .arrange(RIGHT, buff=0.35)
            .shift(UP * 1.05)
        )

        col1 = VGroup(
            txt("small proofs", size=24, color=PAL.text),
            txt("fast verify", size=24, color=PAL.text),
            txt("per-circuit setup", size=24, color=PAL.red),
        ).arrange(DOWN, buff=0.18)
        col2 = VGroup(
            txt("simpler ceremonies", size=24, color=PAL.text),
            txt("different tradeoffs", size=24, color=PAL.text),
        ).arrange(DOWN, buff=0.18)
        col3 = VGroup(
            txt("transparent setup", size=24, color=PAL.text),
            txt("larger proofs", size=24, color=PAL.muted),
        ).arrange(DOWN, buff=0.18)

        col1.next_to(headers[0], DOWN, buff=0.56)
        col2.next_to(headers[1], DOWN, buff=0.56)
        col3.next_to(headers[2], DOWN, buff=0.56)
        col1.set_x(headers[0].get_x())
        col2.set_x(headers[1].get_x())
        col3.set_x(headers[2].get_x())
        cols = VGroup(col1, col2, col3)

        self.play(FadeIn(toxic_ref, shift=DOWN * 0.05), run_time=RT_IN)
        self.play(FadeIn(headers, shift=DOWN * 0.08), run_time=RT_IN)
        self.play(FadeIn(cols, shift=UP * 0.08), run_time=RT_IN)

        takeaway = label_box(
            "Takeaway: ceremonies are a one-time cost to remove toxic waste.",
            font_size=24,
            color=PAL.teal,
        ).to_edge(DOWN)
        self.play(FadeIn(takeaway, shift=UP * 0.12), run_time=RT_IN)
        self.wait(5)

        self.transition_out(title, toxic_ref, headers, cols, takeaway)
