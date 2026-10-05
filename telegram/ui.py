"""Message rendering (Telegram HTML) and inline keyboard building."""
from html import escape as esc
from typing import List

from pyrogram.types import InlineKeyboardButton as Btn
from pyrogram.types import InlineKeyboardMarkup as Markup

from botfunctions import Report


# ---------------------------------------------------------------- small helpers
def bar(det: int, total: int, width: int = 10) -> str:
    if total <= 0:
        return "▱" * width
    filled = round(det / total * width)
    if det and not filled:
        filled = 1
    return "▰" * filled + "▱" * (width - filled)


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
    return f"<{tag}>{chr(10).join(out)}</{tag.split()[0]}>"


def _chunks(items: List[str], n: int = 4) -> List[str]:
    return [" · ".join(esc(x) for x in items[i:i + n]) for i in range(0, len(items), n)]


# ---------------------------------------------------------------- views
def render_main(rep: Report) -> str:
    emoji, label = verdict(rep)
    head = f"{emoji} <b>{label}</b>"
    if not rep.pending:
        head += f"  ·  <b>{rep.det}/{rep.total}</b>\n{bar(rep.det, rep.total)}"
    lines = [head, ""]

    if rep.kind == "file":
        lines.append(f"<b>{esc(rep.title)}</b>")
        sub = " · ".join(x for x in (rep.file_type, fmt_size(rep.size) if rep.size else "") if x)
        if sub:
            lines.append(f"<i>{esc(sub)}</i>")
    else:
        lines.append(f"🔗 <code>{esc(rep.url[:200])}</code>")

    if rep.threat:
        lines.append(f"🏷 <b>Threat:</b> {esc(rep.threat)}")
    if rep.package:
        pkg = f"📦 <code>{esc(rep.package)}</code>"
        if rep.version:
            pkg += f" · v{esc(rep.version)}"
        lines.append(pkg)

    meta = []
    if rep.first_seen:
        meta.append(f"🔬 First seen · {rep.first_seen}")
    if rep.last_seen:
        meta.append(f"🔭 Last analysed · {rep.last_seen}")
    if rep.submitted:
        meta.append(f"🔁 Submitted · {rep.submitted}×")
    if rep.magic:
        meta.append(f"🧩 {esc(rep.magic[:80])}")
    if meta:
        lines += ["", _bq(meta, expandable=False)]

    if rep.pending:
        lines += ["", "⏳ <i>Engines are still scanning. Tap 🔄 Rescan in a moment.</i>"]
    if rep.kind == "file" and rep.sha256:
        lines += ["", f"<code>{rep.sha256}</code>"]
    return "\n".join(lines)


def render_detections(rep: Report) -> str:
    if rep.pending:
        return "🧪 <b>Detections</b>\n\n⏳ <i>Analysis pending. Go back and tap 🔄 Rescan.</i>"
    parts = [f"🧪 <b>Detections</b> · {rep.det}/{rep.total}"]
    if rep.detected:
        parts += ["", "❌ <b>Flagged</b>",
                  _bq([esc(e) for e, _ in rep.detected], limit=1400)]
    if rep.clean:
        parts += ["", f"✅ <b>Clean</b> ({len(rep.clean)})",
                  _bq(_chunks(rep.clean), limit=1500)]
    if rep.unsupported:
        parts += ["", f"⚠️ <b>Unsupported</b> ({len(rep.unsupported)})",
                  _bq(_chunks(rep.unsupported), limit=700)]
    return "\n".join(parts)


def render_signatures(rep: Report) -> str:
    if rep.pending:
        return "🌡 <b>Signatures</b>\n\n⏳ <i>Analysis pending. Go back and tap 🔄 Rescan.</i>"
    if not rep.detected:
        what = "file" if rep.kind == "file" else "URL"
        return f"🌡 <b>Signatures</b>\n\n✅ No engine flagged this {what}."
    lines = [f"<b>{esc(e)}</b>\n╰ {esc(r)}" for e, r in rep.detected]
    return f"🌡 <b>Signatures</b> · {rep.det}\n\n" + _bq(lines, limit=3500)


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
