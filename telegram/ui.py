"""Message rendering (Telegram HTML) and inline keyboard building."""
from html import escape as esc
from typing import List

from pyrogram.types import InlineKeyboardButton as Btn
from pyrogram.types import InlineKeyboardMarkup as Markup

from botfunctions import Report


# ---------------------------------------------------------------- small helpers
def fmt_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.2f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def verdict(rep: Report):
    if rep.pending:
        return "⏳", "Analysis pending"
    if rep.det == 0:
        return "🟢", "Clean"
    if rep.det < 5:
        return "🟡", "Suspicious"
    return "🔴", "Malicious"


def _bq(lines: List[str], limit: int = 3000, expandable: bool = True) -> str:
    """Blockquote that never blows past Telegram's length limit."""
    out, used = [], 0
    for i, line in enumerate(lines):
        if used + len(line) + 1 > limit:
            out.append(f"… +{len(lines) - i} more")
            break
        out.append(line)
        used += len(line) + 1
    tag = "blockquote expandable" if expandable else "blockquote"
    return f"<{tag}>{chr(10).join(out)}</blockquote>"


def _section(emoji: str, title: str, names: List[str], limit: int) -> List[str]:
    """One engine per line, inside a collapsible quote."""
    return ["", f"{emoji} <b>{title}</b> ({len(names)})", _bq([esc(n) for n in names], limit)]


# ---------------------------------------------------------------- views
def render_main(rep: Report) -> str:
    emoji, label = verdict(rep)
    lines = [f"{emoji} <b>{label}</b>"]
    if not rep.pending:
        lines.append(f"🧬 <b>Detections:</b> {rep.det}/{rep.total}")
    lines.append("")

    if rep.kind == "file":
        lines.append("📄 <b>File name:</b>")
        lines.append(f"<code>{esc(rep.title)}</code>")
        lines.append("")
        if rep.file_type:
            lines.append(f"🗂 <b>File type:</b> {esc(rep.file_type)}")
        if rep.size:
            lines.append(f"💾 <b>Size:</b> {fmt_size(rep.size)}")
        if rep.package:
            lines.append(f"📦 <b>Package:</b> <code>{esc(rep.package)}</code>")
        if rep.version:
            lines.append(f"🔖 <b>Version:</b> v{esc(rep.version)}")
    else:
        lines.append(f"🔗 <b>URL:</b> <spoiler>{esc(rep.url[:300])}</spoiler>")

    if rep.threat:
        lines.append(f"☣️ <b>Threat:</b> {esc(rep.threat)}")

    times = []
    if rep.first_seen:
        times.append(f"🔬 <b>First seen:</b> {rep.first_seen}")
    if rep.last_seen:
        times.append(f"🔭 <b>Last analysed:</b> {rep.last_seen}")
    if rep.submitted:
        times.append(f"⏱ <b>Submitted:</b> {rep.submitted}×")
    if times:
        lines += [""] + times

    if rep.magic:
        lines += ["", f"🧩 <b>Magic:</b> {esc(rep.magic[:100])}"]

    if rep.kind == "file" and rep.sha256:
        lines += ["", f"🔐 <b>SHA-256:</b> <spoiler>{rep.sha256}</spoiler>"]

    if rep.pending:
        lines += ["", "⏳ <i>Engines are still scanning. Tap 🔄 Rescan in a moment.</i>"]
    return "\n".join(lines)


def render_detections(rep: Report) -> str:
    if rep.pending:
        return "🧬 <b>Detections</b>\n\n⏳ <i>Analysis pending. Go back and tap 🔄 Rescan.</i>"
    parts = [f"🧬 <b>Detections:</b> {rep.det}/{rep.total}"]
    if rep.detected:
        parts += _section("❌", "Flagged", [e for e, _ in rep.detected], 1100)
    else:
        parts += ["", "✅ <b>No engine flagged this</b> " + ("file" if rep.kind == "file" else "URL")]
    if rep.clean:
        parts += _section("✅", "Clean", rep.clean, 1500)
    if rep.unsupported:
        parts += _section("⚠️", "Unsupported", rep.unsupported, 900)
    return "\n".join(parts)


def render_signatures(rep: Report) -> str:
    if rep.pending:
        return "🌡 <b>Signatures</b>\n\n⏳ <i>Analysis pending. Go back and tap 🔄 Rescan.</i>"
    if not rep.detected:
        what = "file" if rep.kind == "file" else "URL"
        return f"🌡 <b>Signatures</b>\n\n✅ No engine flagged this {what}."
    lines = [f"<b>{esc(e)}</b>\n╰ {esc(r)}" for e, r in rep.detected]
    return f"🌡 <b>Signatures:</b> {rep.det}\n\n" + _bq(lines, limit=3500)


# ---------------------------------------------------------------- keyboard
def _rows(buttons: List[Btn], per_row: int = 3) -> List[List[Btn]]:
    return [buttons[i:i + per_row] for i in range(0, len(buttons), per_row)]


def build_keyboard(rep: Report, view: str = "m", mirrors_open: bool = False) -> Markup:
    kc = "f" if rep.kind == "file" else "u"

    def cb(action: str) -> str:
        return f"{action}{kc}{rep.key}"        # e.g. "df<md5>"  (< 64 bytes)

    vt_btn = Btn("🔗 View on VirusTotal", url=rep.link)
    back = Btn("🔙 Back", callback_data=cb("m"))
    det = Btn("🧪 Detections", callback_data=cb("d"))
    sig = Btn("🌡 Signatures", callback_data=cb("s"))

    if view == "d":
        return Markup([[back, sig], [vt_btn]])
    if view == "s":
        return Markup([[back, det], [vt_btn]])

    rows = [[det, sig]]
    if rep.official:
        rows += _rows([Btn(label, url=url) for label, url in rep.official])

    tools = []
    if rep.package:
        if mirrors_open and rep.mirrors:
            rows.append([Btn(label, url=url) for label, url in rep.mirrors])
            tools.append(Btn("🙈 Hide mirrors", callback_data=cb("h")))
        else:
            tools.append(Btn("🪞 Mirrors", callback_data=cb("x")))
    tools.append(Btn("🔄 Rescan", callback_data=cb("r")))
    rows.append(tools)
    rows.append([vt_btn])
    return Markup(rows)
