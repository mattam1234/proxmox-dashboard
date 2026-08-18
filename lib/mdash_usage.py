"""Admin-only Claude usage and cost view for the media dashboard.

Wiring (in media-dashboard-web.py):

    import mdash_usage

    # in do_GET, after the session check:
    if mdash_usage.handle_get(self, path, qs):
        return

    # in nav(), inside the `if admin:` block:
    out += a("/usage", "Usage")

Every assistant message in a Claude transcript records the model that produced
it and its token counts, split by kind - fresh input, cache writes (separately
for the 5-minute and 1-hour TTLs), cache reads, and output. That is enough to
price a session after the fact, so this page reads the same transcripts the
Claude tab does and needs no separate accounting.

*Costs here are estimates at published list prices*, not an invoice. They are
useful for comparing sessions, models and days against each other; a Claude
Code subscription is not billed per token. Cache writes cost more than fresh
input and cache reads cost far less, so the multipliers below matter more than
the headline rate - a session that looks huge in tokens is often mostly cache
reads at a tenth the price.

Charts are rendered as inline SVG on the server: no chart library, nothing
fetched from a CDN, and it renders with JavaScript off. The palette is the
validated categorical set - hues assigned in fixed order so a model keeps its
colour when the filter changes, never cycled.
"""
import glob
import html
import json
import os
import re
import sys
import threading
import time

PROJECTS_DIR = "/root/.claude/projects"
SID_OK = re.compile(r"^[0-9a-fA-F-]{36}$")

DAY_CHOICES = [7, 14, 30, 90]
DEFAULT_DAYS = 14
TOP_SESSIONS = 12

# Published list prices, US$ per million tokens: (input, output). A model is
# matched by longest prefix, so dated variants fall back to their family.
PRICES = {
    "claude-fable-5": (10.0, 50.0),
    "claude-mythos-5": (10.0, 50.0),
    "claude-mythos-preview": (10.0, 50.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-opus-4": (5.0, 25.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-sonnet-4": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-haiku": (1.0, 5.0),
}
# Sonnet 5 runs at an introductory rate through this date, so each day is
# priced at the rate that was in force on that day rather than today's.
INTRO = {"claude-sonnet-5": ((2.0, 10.0), "2026-08-31")}

# Cache multipliers on the input rate: a 5-minute write costs 1.25x, a 1-hour
# write 2x, and a read a tenth.
W5, W1H, READ = 1.25, 2.0, 0.1

_cache = {}                       # transcript path -> (size, mtime, per-file rollup)
_lock = threading.Lock()

# Categorical slots in fixed order (light, dark). Validated as a set against
# this dashboard's own card colours: every adjacent pair clears the CVD and
# normal-vision floors in both modes. In light mode aqua and yellow fall below
# 3:1 on the surface, which obliges the relief this page already ships -
# a legend, direct labels, and the table view underneath.
SERIES = [("#2a78d6", "#3987e5"), ("#eb6834", "#d95926"),
          ("#1baf7a", "#199e70"), ("#eda100", "#c98500"),
          ("#e87ba4", "#d55181"), ("#008300", "#008300"),
          ("#4a3aa7", "#9085e9"), ("#e34948", "#e66767")]
KIND_LABEL = [("in", "fresh input"), ("cw", "cache write"),
              ("cr", "cache read"), ("out", "output")]


def _main_attr(name, default=None):
    """Borrow nav()/CSS from the dashboard script without importing it."""
    return getattr(sys.modules.get("__main__"), name, default)


def _rate(model, day):
    """(input, output) $/Mtok for a model on a given YYYY-MM-DD."""
    best = None
    for prefix, price in PRICES.items():
        if model.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, price)
    if not best:
        return None
    prefix, price = best
    intro = INTRO.get(prefix)
    if intro and day and day <= intro[1]:
        return intro[0]
    return price


def _blank():
    return {"in": 0, "cw5": 0, "cw1h": 0, "cr": 0, "out": 0, "think": 0,
            "msgs": 0, "cost": 0.0}


def _add(dst, src):
    for k in ("in", "cw5", "cw1h", "cr", "out", "think", "msgs"):
        dst[k] += src[k]
    dst["cost"] += src["cost"]


def _usage_of(entry):
    """Token counts from one assistant transcript line, or None."""
    msg = entry.get("message") or {}
    u = msg.get("usage")
    if not isinstance(u, dict):
        return None
    cc = u.get("cache_creation")
    if isinstance(cc, dict):
        cw5 = cc.get("ephemeral_5m_input_tokens") or 0
        cw1h = cc.get("ephemeral_1h_input_tokens") or 0
    else:
        # Older transcripts report only the total; treat it as the 5m tier.
        cw5, cw1h = u.get("cache_creation_input_tokens") or 0, 0
    details = u.get("output_tokens_details") or {}
    return {"in": u.get("input_tokens") or 0, "cw5": cw5, "cw1h": cw1h,
            "cr": u.get("cache_read_input_tokens") or 0,
            "out": u.get("output_tokens") or 0,
            "think": details.get("thinking_tokens") or 0,
            "msgs": 1, "cost": 0.0}


def _scan_file(path):
    """Roll one transcript up into {(day, model): counts} plus session meta."""
    rows, title, first_day, last = {}, "", "", 0
    try:
        with open(path, "rb") as f:
            for raw in f:
                if not raw.strip():
                    continue
                try:
                    d = json.loads(raw.decode("utf-8", "replace"))
                except Exception:
                    continue
                if not title:
                    if d.get("type") == "ai-title" and d.get("title"):
                        title = str(d["title"])[:120]
                    elif d.get("type") == "user" and not d.get("isMeta"):
                        c = (d.get("message") or {}).get("content")
                        t = c if isinstance(c, str) else ""
                        if isinstance(c, list):
                            for b in c:
                                if isinstance(b, dict) and b.get("type") == "text":
                                    t = b.get("text") or ""
                                    break
                        t = (t or "").strip()
                        if t and not t.startswith("<"):
                            title = " ".join(t.split())[:120]
                if d.get("type") != "assistant":
                    continue
                u = _usage_of(d)
                if not u:
                    continue
                day = (d.get("timestamp") or "")[:10]
                model = ((d.get("message") or {}).get("model") or "unknown")
                if not first_day or (day and day < first_day):
                    first_day = day
                last = max(last, 1)
                rate = _rate(model, day)
                if rate:
                    inr, outr = rate
                    u["cost"] = (u["in"] * inr + u["cw5"] * inr * W5
                                 + u["cw1h"] * inr * W1H + u["cr"] * inr * READ
                                 + u["out"] * outr) / 1e6
                key = (day, model)
                if key not in rows:
                    rows[key] = _blank()
                _add(rows[key], u)
    except OSError:
        return None
    return {"rows": rows, "title": title or "(no prompt)", "first": first_day}


def _rollups():
    """Per-transcript rollups for every session, cached on size+mtime."""
    out = {}
    for path in glob.glob(os.path.join(PROJECTS_DIR, "*", "*.jsonl")):
        sid = os.path.basename(path)[:-6]
        if not SID_OK.match(sid):
            continue
        try:
            st = os.stat(path)
        except OSError:
            continue
        key = (st.st_size, int(st.st_mtime))
        with _lock:
            hit = _cache.get(path)
        if hit and hit[0] == key:
            out[sid] = (hit[1], st.st_mtime)
            continue
        roll = _scan_file(path)
        if roll is None:
            continue
        with _lock:
            _cache[path] = (key, roll)
        out[sid] = (roll, st.st_mtime)
    return out


def aggregate(days=DEFAULT_DAYS):
    """Totals by day, model and session over the trailing `days` window."""
    cutoff = time.strftime("%Y-%m-%d",
                           time.gmtime(time.time() - days * 86400))
    by_day, by_model, by_session, totals = {}, {}, {}, _blank()

    for sid, (roll, mtime) in _rollups().items():
        s_tot, s_models = _blank(), {}
        for (day, model), counts in roll["rows"].items():
            if not day or day < cutoff:
                continue
            _add(totals, counts)
            _add(by_day.setdefault(day, {}).setdefault(model, _blank()), counts)
            _add(by_model.setdefault(model, _blank()), counts)
            _add(s_tot, counts)
            _add(s_models.setdefault(model, _blank()), counts)
        if s_tot["msgs"]:
            top = max(s_models.items(), key=lambda kv: kv[1]["cost"])[0]
            by_session[sid] = {"id": sid, "title": roll["title"], "model": top,
                               "mtime": int(mtime), **s_tot}

    # Fill empty days so the time axis has no silent gaps.
    day_list = []
    now = time.time()
    for i in range(days - 1, -1, -1):
        d = time.strftime("%Y-%m-%d", time.gmtime(now - i * 86400))
        day_list.append({"day": d, "models": by_day.get(d, {}),
                         "cost": sum(v["cost"] for v in by_day.get(d, {}).values()),
                         "in": sum(v["in"] for v in by_day.get(d, {}).values()),
                         "cw": sum(v["cw5"] + v["cw1h"] for v in by_day.get(d, {}).values()),
                         "cr": sum(v["cr"] for v in by_day.get(d, {}).values()),
                         "out": sum(v["out"] for v in by_day.get(d, {}).values())})

    # Transcripts carry placeholder model names (e.g. <synthetic>) for turns
    # that never hit the API. They have no tokens and no cost, so they would
    # only take a colour slot in the legend.
    models = sorted(((m, c) for m, c in by_model.items()
                     if c["in"] + c["cw5"] + c["cw1h"] + c["cr"] + c["out"] > 0),
                    key=lambda kv: -kv[1]["cost"])
    # Ranked by tokens, not cost: on a subscription the tokens are what the
    # session actually consumed.
    sessions = sorted(by_session.values(),
                      key=lambda s: -(s["in"] + s["cw5"] + s["cw1h"]
                                      + s["cr"] + s["out"]))
    return {"days": day_list, "models": models, "sessions": sessions,
            "totals": totals, "window": days,
            "priced": bool(totals["msgs"])}


# ------------------------------------------------------------------ drawing
def _plan_window():
    """Subscription usage window, if a dashboard run has reported one.

    Claude only emits this on a live run stream, so it is captured by the run
    reader in mdash_claude and is absent until a run has gone through this
    dashboard. Returns a stat tile tuple or None.
    """
    try:
        import mdash_claude
        snap = mdash_claude.rate_limit_snapshot()
    except Exception:
        return None
    if not snap:
        return None
    kind = (snap.get("kind") or "").replace("_", "-")
    status = (snap.get("status") or "unknown").replace("_", " ")
    resets = snap.get("resets")
    left = ""
    if isinstance(resets, (int, float)):
        secs = int(resets - time.time())
        if secs > 0:
            left = f", resets in {secs // 3600}h {secs % 3600 // 60:02d}m"
    age = int(time.time() - (snap.get("seen") or 0))
    when = f"{age // 60}m ago" if age >= 60 else "just now"
    return (f"Plan window ({kind or 'subscription'})", status.title(),
            f"seen {when}{left}")


def _money(v):
    if v >= 100:
        return f"${v:,.0f}"
    if v >= 1:
        return f"${v:,.2f}"
    return f"${v:.3f}"


def _compact(n):
    n = float(n)
    for unit, size in (("B", 1e9), ("M", 1e6), ("K", 1e3)):
        if n >= size:
            v = n / size
            return f"{v:.1f}{unit}" if v < 10 else f"{v:.0f}{unit}"
    return f"{n:,.0f}"


def _nice_ticks(top, count=4):
    """Round axis maximum up to a clean number and step to it."""
    if top <= 0:
        return [0], 1.0
    import math
    raw = top / count
    mag = 10 ** math.floor(math.log10(raw))
    for mult in (1, 2, 2.5, 5, 10):
        step = mag * mult
        if step * count >= top:
            break
    return [step * i for i in range(count + 1)], step * count


def _cap_path(x, y, w, h, r=4):
    """Bar with a rounded data-end and square shoulders at the baseline."""
    r = max(0, min(r, h, w / 2))
    if h <= 0:
        return ""
    return (f"M{x:.1f},{y + h:.1f} L{x:.1f},{y + r:.1f} "
            f"Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} "
            f"L{x + w - r:.1f},{y:.1f} Q{x + w:.1f},{y:.1f} "
            f"{x + w:.1f},{y + r:.1f} L{x + w:.1f},{y + h:.1f} Z")


def _stacked_svg(rows, keys, colors, labels, fmt, title_fmt, height=210):
    """Stacked column chart: one column per day, one segment per key.

    `rows` is [{'label':…, 'values':{key: number}}]; segments are separated by a
    2px gap in the surface colour rather than a stroke, and only the topmost
    segment of each column carries the rounded data-end.
    """
    W, H = 760, height
    pad_l, pad_r, pad_t, pad_b = 52, 10, 16, 26
    plot_w, plot_h = W - pad_l - pad_r, H - pad_t - pad_b
    totals = [sum(max(0, r["values"].get(k, 0)) for k in keys) for r in rows]
    ticks, top = _nice_ticks(max(totals) if totals else 0)
    band = plot_w / max(1, len(rows))
    bw = min(24.0, band * 0.62)

    out = [f'<svg viewBox="0 0 {W} {H}" class="chart" role="img" '
           f'preserveAspectRatio="xMidYMid meet">']
    # Gridlines and y ticks - hairline, solid, recessive.
    for t in ticks:
        y = pad_t + plot_h - (t / top * plot_h if top else 0)
        out.append(f'<line class="grid" x1="{pad_l}" y1="{y:.1f}" '
                   f'x2="{W - pad_r}" y2="{y:.1f}"/>')
        out.append(f'<text class="tick" x="{pad_l - 8}" y="{y + 3.5:.1f}" '
                   f'text-anchor="end">{html.escape(fmt(t))}</text>')

    peak = max(range(len(rows)), key=lambda i: totals[i]) if totals else -1
    for i, r in enumerate(rows):
        cx = pad_l + band * i + (band - bw) / 2
        y = pad_t + plot_h
        drawn = [k for k in keys if r["values"].get(k, 0) > 0]
        for k in keys:
            v = max(0, r["values"].get(k, 0))
            if not v or not top:
                continue
            h = v / top * plot_h
            is_top = k == drawn[-1]
            # 2px surface gap between touching segments.
            gap = 0 if is_top else 2
            seg_h = max(1.0, h - gap)
            y -= h
            path = (_cap_path(cx, y, bw, seg_h) if is_top
                    else f'<rect x="{cx:.1f}" y="{y:.1f}" width="{bw:.1f}" '
                         f'height="{seg_h:.1f}"/>')
            tip = html.escape(title_fmt(r, k, v))
            body = (f'<path d="{path}"/>' if is_top else path)
            out.append(f'<g class="seg" fill="{colors[k]}" data-tip="{tip}">'
                       f'{body}</g>')
        # Label only the peak column, so labels stay sparing and legible.
        if i == peak and totals[i] > 0:
            out.append(f'<text class="peak" x="{cx + bw / 2:.1f}" '
                       f'y="{y - 6:.1f}" text-anchor="middle">'
                       f'{html.escape(fmt(totals[i]))}</text>')

    # X labels: thin them out rather than let them collide.
    every = max(1, len(rows) // 10)
    for i, r in enumerate(rows):
        if i % every:
            continue
        cx = pad_l + band * i + band / 2
        out.append(f'<text class="tick" x="{cx:.1f}" y="{H - 8}" '
                   f'text-anchor="middle">{html.escape(r["label"])}</text>')
    out.append(f'<line class="axis" x1="{pad_l}" y1="{pad_t + plot_h}" '
               f'x2="{W - pad_r}" y2="{pad_t + plot_h}"/>')
    out.append("</svg>")
    return "".join(out)


def _hbar_svg(items, colors, height_per=30, value_fmt=None):
    """Horizontal bars with the value direct-labelled at each tip."""
    if not items:
        return ""
    W = 760
    pad_l, pad_r, pad_t = 132, 74, 6
    H = pad_t * 2 + height_per * len(items)
    top = max(v for _, v, _ in items) or 1
    plot_w = W - pad_l - pad_r
    out = [f'<svg viewBox="0 0 {W} {H}" class="chart" role="img" '
           f'preserveAspectRatio="xMidYMid meet">']
    for i, (name, value, sub) in enumerate(items):
        y = pad_t + height_per * i
        bh = min(24, height_per - 10)
        w = max(2.0, value / top * plot_w)
        out.append(f'<text class="rowlab" x="{pad_l - 10}" y="{y + bh / 2 + 4:.1f}" '
                   f'text-anchor="end">{html.escape(name)}</text>')
        # Rounded data-end on the right, square at the baseline on the left.
        r = min(4, bh / 2)
        out.append(f'<g class="seg" fill="{colors[i % len(colors)]}" '
                   f'data-tip="{html.escape(sub)}">'
                   f'<path d="M{pad_l},{y:.1f} L{pad_l + w - r:.1f},{y:.1f} '
                   f'Q{pad_l + w:.1f},{y:.1f} {pad_l + w:.1f},{y + r:.1f} '
                   f'L{pad_l + w:.1f},{y + bh - r:.1f} '
                   f'Q{pad_l + w:.1f},{y + bh:.1f} {pad_l + w - r:.1f},{y + bh:.1f} '
                   f'L{pad_l},{y + bh:.1f} Z"/></g>')
        shown = (value_fmt or _money)(value)
        out.append(f'<text class="val" x="{pad_l + w + 8:.1f}" '
                   f'y="{y + bh / 2 + 4:.1f}">{html.escape(shown)}</text>')
    out.append("</svg>")
    return "".join(out)


def _legend(pairs):
    """A legend for two or more series. One series needs none - the heading
    already names what is plotted, and a lone swatch just restates it."""
    if len(pairs) < 2:
        return ""
    return ('<div class="legend">' + "".join(
        f'<span class="lg"><i style="background:{c}"></i>{html.escape(n)}</span>'
        for n, c in pairs) + "</div>")


def _spark(values, w=260, h=54):
    """Trend line for the hero figure: 2px line, 10% wash, end-dot ringed."""
    if len(values) < 2 or max(values) <= 0:
        return ""
    top = max(values)
    step = w / (len(values) - 1)
    pts = [(i * step, h - (v / top * (h - 8)) - 4) for i, v in enumerate(values)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = f"M0,{h} L" + line.replace(" ", " L") + f" L{w},{h} Z"
    lx, ly = pts[-1]
    return (f'<svg class="spark" viewBox="0 0 {w} {h}" '
            f'preserveAspectRatio="none" aria-hidden="true">'
            f'<path class="sparea" d="{area}"/>'
            f'<polyline class="sparkline" points="{line}"/>'
            f'<circle class="sparkdot" cx="{lx:.1f}" cy="{ly:.1f}" r="4"/></svg>')


CSS = """
.uz{--s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;--s4:#eda100;
  --grid:#e1e0d9;--axis:#c3c2b7;--tickink:#898781}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]) .uz{
  --s1:#3987e5;--s2:#d95926;--s3:#199e70;--s4:#c98500;
  --grid:#2c2c2a;--axis:#383835;--tickink:#898781}}
:root[data-theme="dark"] .uz{--s1:#3987e5;--s2:#d95926;--s3:#199e70;
  --s4:#c98500;--grid:#2c2c2a;--axis:#383835;--tickink:#898781}
.uz .filters{display:flex;gap:6px;align-items:center;flex-wrap:wrap;
  margin:0 0 16px}
.uz .filters a{font-size:12.5px;padding:5px 12px;border-radius:999px;
  border:1px solid var(--line);color:var(--muted);text-decoration:none}
.uz .filters a.on{border-color:var(--accent);color:var(--fg);font-weight:600;
  background:color-mix(in srgb,var(--accent) 10%,transparent)}
.uz .filters a:hover{border-color:var(--accent)}
/* Hero and tiles borrow the dashboard's own card treatment (radius, shadow)
   so this page reads as part of the same UI rather than a bolted-on view. */
.hero{background:var(--card);border:1px solid var(--line);
  border-radius:var(--r);box-shadow:var(--shadow);
  padding:18px 20px;margin-bottom:12px;display:flex;gap:20px;
  align-items:flex-end;justify-content:space-between;flex-wrap:wrap}
.hero .lab{font-size:12px;color:var(--muted);text-transform:uppercase;
  letter-spacing:.07em}
.hero .fig{font-size:52px;line-height:1.05;font-weight:650;margin-top:4px;
  letter-spacing:-.02em}
.hero .sub{font-size:13px;color:var(--muted);margin-top:6px}
.heroR{flex:0 1 260px;min-width:180px}
.spark{width:100%;height:54px;display:block;overflow:visible}
.sparkline{fill:none;stroke:var(--s1);stroke-width:2;stroke-linejoin:round;
  stroke-linecap:round}
.sparea{fill:var(--s1);opacity:.10}
.sparkdot{fill:var(--s1);stroke:var(--card);stroke-width:2}
.sparklab{font-size:11px;color:var(--muted);text-align:right;margin-top:4px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:10px;margin-bottom:16px}
.tile{background:var(--card);border:1px solid var(--line);
  border-radius:var(--r);box-shadow:var(--shadow);padding:12px 14px}
.tile .lab{font-size:11px;color:var(--muted);text-transform:uppercase;
  letter-spacing:.06em}
.tile .val{font-size:23px;font-weight:600;margin-top:3px;letter-spacing:-.01em}
.tile .sub{font-size:11.5px;color:var(--muted);margin-top:2px}
/* .card and .card h2 are the dashboard's own components - deliberately not
   redefined here, so section headings match every other page. */
.uz .card{margin-bottom:12px;padding:16px 18px}
.uz .card h2{margin:0 0 3px}
.uz .cap{font-size:12.5px;color:var(--muted);margin:0 0 14px;line-height:1.5}
.chart{width:100%;height:auto;display:block;overflow:visible}
.chart .grid{stroke:var(--grid);stroke-width:1}
.chart .axis{stroke:var(--axis);stroke-width:1}
.chart .tick{fill:var(--tickink);font-size:11px;
  font-variant-numeric:tabular-nums}
.chart .peak,.chart .val{fill:var(--fg);font-size:11.5px;font-weight:600}
.chart .rowlab{fill:var(--muted);font-size:12px}
.chart .seg{transition:opacity .12s}
.chart:hover .seg{opacity:.55}
.chart .seg:hover{opacity:1}
.legend{display:flex;gap:14px;flex-wrap:wrap;margin-top:10px;font-size:12px;
  color:var(--muted)}
.legend .lg{display:flex;align-items:center;gap:6px}
.legend i{width:10px;height:10px;border-radius:3px;display:inline-block}
.utab{width:100%;border-collapse:collapse;font-size:13px}
.utab th{text-align:left;font-size:11px;text-transform:uppercase;
  letter-spacing:.06em;color:var(--muted);font-weight:600;padding:0 10px 8px 0;
  border-bottom:1px solid var(--line)}
.utab td{padding:9px 10px 9px 0;border-bottom:1px solid var(--line);
  vertical-align:top}
.utab tr:last-child td{border-bottom:0}
.utab .num{text-align:right;font-variant-numeric:tabular-nums;
  white-space:nowrap}
.utab .ti{font-weight:600;display:block;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;max-width:44ch}
.utab .mu{color:var(--muted);font-size:11.5px}
.dot{width:9px;height:9px;border-radius:3px;display:inline-block;
  margin-right:7px;vertical-align:baseline}
#tip{position:fixed;pointer-events:none;opacity:0;transition:opacity .1s;
  background:var(--fg);color:var(--bg);font-size:12px;padding:5px 9px;
  border-radius:6px;z-index:50;max-width:280px;font-variant-numeric:tabular-nums}
.note{font-size:12px;color:var(--muted);margin-top:14px;line-height:1.6}
.empty{color:var(--muted);font-size:13px;padding:26px 0;text-align:center}
@media(max-width:760px){.hero .fig{font-size:40px}
/* Seven columns will not fit a phone, so table.resp (shared core) stacks each
   session into a card; these re-align the figures, which .utab right-aligns for
   the desktop table but which read better beside their label when stacked. */
.utab.resp tr{border-bottom:1px solid var(--line);padding:11px 0}
.utab.resp td{padding:2px 0;border:0}
.utab.resp td.num{text-align:left}
.utab.resp .ti{white-space:normal;overflow:visible;text-overflow:clip}
}
"""

JS = """
// Hover layer: one tooltip element, positioned from the segment under the
// pointer. Charts are server-rendered, so the page is fully readable without
// this - it only adds the per-segment detail.
const tip=document.getElementById('tip');
function show(e){
  const g=e.target.closest('.seg'); if(!g)return;
  tip.textContent=g.dataset.tip||''; tip.style.opacity='1';
  const pad=14;
  let x=e.clientX+pad, y=e.clientY+pad;
  const w=tip.offsetWidth, h=tip.offsetHeight;
  if(x+w>innerWidth-8)x=e.clientX-w-pad;
  if(y+h>innerHeight-8)y=e.clientY-h-pad;
  tip.style.left=x+'px'; tip.style.top=y+'px';
}
document.querySelectorAll('.chart').forEach(c=>{
  c.addEventListener('mousemove',show);
  c.addEventListener('mouseleave',()=>{tip.style.opacity='0';});
});
"""

PAGE = """<!doctype html>
<meta charset="utf-8"><title>Usage</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>__CSS__</style>
<div class="wrap uz">
__NAV__
<h1>Claude usage</h1>
<p class="sub">Every session on this host, counted from its own transcript.
Subscription plan &mdash; token counts are exact, prices are reference only.</p>
__BODY__
</div>
<div id="tip"></div>
<script>__JS__</script>
"""


def _render(data):
    days, models, sessions = data["days"], data["models"], data["sessions"]
    tot = data["totals"]
    win = data["window"]

    if not tot["msgs"]:
        return ('<div class="card"><div class="empty">No Claude usage recorded '
                f'in the last {win} days.</div></div>')

    # Colour by model identity, fixed order, so a model keeps its hue when the
    # window changes and a model drops out.
    model_names = [m for m, _ in models]
    light = {m: SERIES[i % len(SERIES)][0] for i, m in enumerate(model_names)}
    short = {m: m.replace("claude-", "") for m in model_names}

    cached = tot["cr"]
    total_tok = tot["in"] + tot["cw5"] + tot["cw1h"] + tot["cr"] + tot["out"]
    cache_pct = (cached / total_tok * 100) if total_tok else 0
    active_days = sum(1 for d in days if d["cost"] > 0)
    per_day = tot["cost"] / max(1, active_days)

    out = []
    out.append('<div class="filters"><span class="lab" style="font-size:12px;'
               'color:var(--muted);margin-right:4px">Window</span>')
    for n in DAY_CHOICES:
        on = " on" if n == win else ""
        out.append(f'<a class="f{on}" href="/usage?days={n}">{n} days</a>')
    out.append("</div>")

    # Tokens are the headline, not dollars: this host runs on a Claude
    # subscription, where nothing is billed per token. The list-price figure
    # stays on the page as a way to weigh sessions against each other.
    out.append(
        '<div class="hero"><div class="heroL">'
        f'<div class="lab">Tokens used, last {win} days</div>'
        f'<div class="fig">{_compact(total_tok)}</div>'
        f'<div class="sub">{len(sessions)} '
        f'session{"" if len(sessions) == 1 else "s"} &middot; '
        f'{tot["msgs"]:,} assistant turns &middot; '
        f'{_compact(total_tok / max(1, active_days))} per active day</div></div>'
        f'<div class="heroR">{_spark([d["in"] + d["cw"] + d["cr"] + d["out"] for d in days])}'
        f'<div class="sparklab">daily tokens, last {win} days</div></div></div>')

    window = _plan_window()
    out.append('<div class="tiles">')
    tiles = [
        ("Output tokens", _compact(tot["out"]),
         f'{_compact(tot["think"])} of it thinking'),
        ("Cache reads", _compact(tot["cr"]),
         f"{cache_pct:.0f}% of all tokens, replayed context"),
        ("Cache writes", _compact(tot["cw5"] + tot["cw1h"]),
         f'{_compact(tot["cw1h"])} on the 1-hour tier'),
        ("Fresh input", _compact(tot["in"]), "new context, never cached"),
    ]
    if window:
        tiles.append(window)
    tiles.append(("List-price equivalent", _money(tot["cost"]),
                  "what this would cost on API billing"))
    for lab, val, sub in tiles:
        out.append(f'<div class="tile"><div class="lab">{lab}</div>'
                   f'<div class="val">{val}</div><div class="sub">{sub}</div></div>')
    out.append("</div>")

    # --- tokens per day, stacked by model
    rows = [{"label": d["day"][8:10] + "/" + d["day"][5:7],
             "day": d["day"],
             "values": {m: sum(d["models"].get(m, {}).get(k, 0)
                               for k in ("in", "cw5", "cw1h", "cr", "out"))
                        for m in model_names}} for d in days]
    colors = {m: f"var(--s{(i % 4) + 1})" if i < 4 else light[m]
              for i, m in enumerate(model_names)}
    # Slots beyond the four themed ones fall back to their fixed hex.
    for i, m in enumerate(model_names):
        if i >= 4:
            colors[m] = light[m]
    # With a single model this chart would restate the by-kind chart below it,
    # so it only appears once there is a split worth seeing.
    if len(model_names) > 1:
        out.append('<div class="card"><h2>Tokens per day, by model</h2>'
                   '<p class="cap">Which model the work went to.</p>')
        out.append(_stacked_svg(
            rows, model_names, colors, [short[m] for m in model_names], _compact,
            lambda r, k, v: f"{r['day']} · {short[k]} · {v:,.0f} tokens"))
        out.append(_legend([(short[m], colors[m]) for m in model_names]))
        out.append("</div>")

    # --- tokens per day, stacked by kind
    krows = [{"label": d["day"][8:10] + "/" + d["day"][5:7], "day": d["day"],
              "values": {"in": d["in"], "cw": d["cw"], "cr": d["cr"],
                         "out": d["out"]}} for d in days]
    kcolors = {"in": "var(--s1)", "cw": "var(--s2)", "cr": "var(--s3)",
               "out": "var(--s4)"}
    klabels = dict(KIND_LABEL)
    onemodel = ("" if len(model_names) > 1
                else f" All of it on {short[model_names[0]]}.")
    out.append('<div class="card"><h2>Tokens per day, by kind</h2>'
               '<p class="cap">Cache reads are replayed context and usually '
               'dominate the count, so a tall day is not necessarily an '
               f'expensive one.{onemodel}</p>')
    out.append(_stacked_svg(
        krows, [k for k, _ in KIND_LABEL], kcolors,
        [l for _, l in KIND_LABEL], _compact,
        lambda r, k, v: f"{r['day']} · {klabels[k]} · {v:,.0f} tokens"))
    out.append(_legend([(l, kcolors[k]) for k, l in KIND_LABEL]))
    out.append("</div>")

    # --- model split. With one model this card would be a single bar restating
    # the hero figure, so it only appears once there is a split to show.
    if len(models) > 1:
        items = [(short[m],
                  c["in"] + c["cw5"] + c["cw1h"] + c["cr"] + c["out"],
                  f'{short[m]} · {c["msgs"]:,} turns · '
                  f'{_money(c["cost"])} at list prices')
                 for m, c in models]
        out.append('<div class="card"><h2>Split by model</h2>'
                   '<p class="cap">Total tokens over the window.</p>')
        out.append(_hbar_svg(items, [colors[m] for m in model_names],
                             value_fmt=_compact))
        out.append("</div>")

    # --- top sessions (also the table view the palette's light mode obliges)
    out.append('<div class="card"><h2>Heaviest sessions</h2>'
               '<p class="cap">Every number above in exact form.</p>'
               '<table class="utab resp"><tr class="hd"><th>Session</th><th>Model</th>'
               '<th class="num">Turns</th><th class="num">Output</th>'
               '<th class="num">Cache read</th><th class="num">Tokens</th>'
               '<th class="num">List price</th></tr>')
    for s in sessions[:TOP_SESSIONS]:
        tk = s["in"] + s["cw5"] + s["cw1h"] + s["cr"] + s["out"]
        when = time.strftime("%d %b %H:%M", time.localtime(s["mtime"]))
        out.append(
            f'<tr><td><span class="ti">{html.escape(s["title"])}</span>'
            f'<span class="mu">{s["id"][:8]} &middot; {when}</span></td>'
            f'<td data-label="Model"><span class="dot" style="background:'
            f'{colors.get(s["model"], "var(--muted)")}"></span>'
            f'<span class="mu">{html.escape(short.get(s["model"], s["model"]))}'
            f'</span></td>'
            f'<td class="num" data-label="Turns">{s["msgs"]:,}</td>'
            f'<td class="num" data-label="Output">{_compact(s["out"])}</td>'
            f'<td class="num" data-label="Cache read">{_compact(s["cr"])}</td>'
            f'<td class="num" data-label="Tokens">{_compact(tk)}</td>'
            f'<td class="num" data-label="List price">{_money(s["cost"])}</td></tr>')
    out.append("</table>")
    out.append('<p class="note">This host runs on a Claude subscription, so '
               '<b>nothing here is billed per token and no figure on this page '
               'is money owed</b>. The list-price column prices each session as '
               'if it had gone through API billing - cache writes at 1.25x '
               'fresh input (2x on the 1-hour tier), cache reads at 0.1x - '
               'which is a fair way to weigh sessions against each other. '
               'Token counts come from each transcript and are exact.</p>')
    out.append("</div>")
    return "".join(out)


# -------------------------------------------------------------------- routing
def handle_get(h, path, qs):
    """Handle a usage route. Returns True when it took the request."""
    if path not in ("/usage", "/api/usage"):
        return False
    if not h.is_admin():
        if path.startswith("/api/"):
            h.send_body('{"error":"forbidden"}', 403, "application/json")
        else:
            h.send_body("<h1>403</h1><p>Admins only.</p>", 403)
        return True

    from urllib.parse import parse_qs
    try:
        days = int((parse_qs(qs).get("days") or [DEFAULT_DAYS])[0])
    except ValueError:
        days = DEFAULT_DAYS
    if days not in DAY_CHOICES:
        days = DEFAULT_DAYS

    data = aggregate(days)
    if path == "/api/usage":
        h.send_body(json.dumps({
            "window": days, "totals": data["totals"],
            "days": [{k: v for k, v in d.items() if k != "models"}
                     for d in data["days"]],
            "models": [{"model": m, **c} for m, c in data["models"]],
            "sessions": data["sessions"][:TOP_SESSIONS],
        }), 200, "application/json")
        return True

    nav = _main_attr("nav")
    page = PAGE.replace("__CSS__", _main_attr("CSS", "") + CSS)
    page = page.replace("__NAV__", nav("/usage", h.current_user(), True) if nav else "")
    page = page.replace("__BODY__", _render(data))
    page = page.replace("__JS__", JS)
    h.send_body(page)
    return True
