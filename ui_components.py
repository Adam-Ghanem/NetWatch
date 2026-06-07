from __future__ import annotations


def animated_letters(text: str, start: int = 0) -> str:
    parts: list[str] = []
    index = start
    for char in text:
        if char == " ":
            parts.append('<span class="word-gap"></span>')
            continue
        safe = char.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        parts.append(f'<span class="letter" style="--i:{index}">{safe}</span>')
        index += 1
    return "".join(parts)


def premium_css() -> str:
    return r"""
<style>
:root{--paper:#f6f1e7;--ink:#10100f;--muted:#6f675e;--cream:#fffdf8;--glow:#d7ff59}
.stApp{background:radial-gradient(circle at 88% 7%,rgba(215,255,89,.34),transparent 18%),linear-gradient(90deg,rgba(16,16,15,.045) 1px,transparent 1px),linear-gradient(180deg,rgba(16,16,15,.045) 1px,transparent 1px),var(--paper)!important;background-size:auto,42px 42px,42px 42px!important;color:var(--ink)!important}
.block-container{max-width:1440px!important;padding:1.6rem 2.4rem 3rem!important}.main .block-container{padding-left:2.8rem!important;padding-right:2.8rem!important}
div[data-testid="stSidebarContent"]{background:#fff!important;border-right:2px solid var(--ink)!important;padding:1.1rem .9rem!important}div[data-testid="stSidebarContent"] img{display:none!important}div[data-testid="stSidebarContent"] *{color:var(--ink)!important}
div[role="radiogroup"] label{border:1.7px solid transparent;border-radius:999px;padding:.32rem .6rem;margin:.12rem 0}div[role="radiogroup"] label:hover{border-color:var(--ink);background:var(--paper)}
.brand-card{border:2px solid var(--ink);border-radius:22px;background:var(--paper);padding:1.1rem 1.15rem;margin:.45rem 0 1.35rem;box-shadow:6px 6px 0 var(--ink)}.brand-eyebrow{font-size:.72rem;letter-spacing:.18em;text-transform:uppercase;font-weight:900;color:var(--muted)!important}.brand-title{font-size:1.75rem;font-weight:950;letter-spacing:-.07em;line-height:1}.brand-sub{font-size:.9rem;color:var(--muted)!important;margin-top:.45rem}
.hero-shell{border:2.5px solid var(--ink);border-radius:30px;background:var(--cream);box-shadow:13px 13px 0 var(--ink);overflow:hidden;margin-bottom:1.4rem}.hero-top{display:grid;grid-template-columns:1.55fr .82fr;border-bottom:2.5px solid var(--ink);min-height:430px}.hero-main{padding:1.7rem 1.9rem 1.55rem}.kicker{font-size:.82rem;letter-spacing:.18em;text-transform:uppercase;font-weight:950;margin-bottom:1.1rem}.hero-title-wrap{overflow:hidden;max-width:1050px}.hero-line{display:block;line-height:.85;overflow:hidden}.letter{display:inline-block;font-size:clamp(4.4rem,8vw,8.2rem);font-weight:950;letter-spacing:-.085em;line-height:.86;transform:translateY(-150%) rotate(-2deg);filter:blur(8px);opacity:0;animation:letterDrop 1.65s cubic-bezier(.16,1,.24,1) forwards;animation-delay:calc(var(--i) * 58ms)}.word-gap{display:inline-block;width:.26em}@keyframes letterDrop{0%{transform:translateY(-150%) rotate(-3deg);filter:blur(10px);opacity:0}56%{transform:translateY(12%) rotate(.4deg);filter:blur(0);opacity:1}78%{transform:translateY(-3%);opacity:1}100%{transform:translateY(0);filter:blur(0);opacity:1}}
.hero-copy{font-size:clamp(1.12rem,1.7vw,1.55rem);line-height:1.25;color:var(--muted);max-width:900px;margin-top:1.35rem}.pill-row{margin-top:1.25rem}.pill{display:inline-block;border:2px solid var(--ink);border-radius:999px;background:#fff;color:var(--ink);padding:.52rem .83rem;margin:.35rem .45rem 0 0;font-size:.82rem;font-weight:950;letter-spacing:.04em;text-transform:uppercase}.pill.dark{background:var(--ink);color:var(--paper)}
.hero-side{background:var(--ink);color:var(--paper);padding:1.35rem;position:relative;overflow:hidden}.hero-side:before{content:"";position:absolute;right:-40px;top:-50px;width:220px;height:220px;border-radius:50%;background:var(--glow);filter:blur(3px);opacity:.95}.console{position:relative;z-index:2;border:1.5px solid rgba(246,241,231,.3);border-radius:22px;padding:1.2rem;background:rgba(255,255,255,.06);backdrop-filter:blur(8px)}.console-title{font-size:.75rem;letter-spacing:.18em;text-transform:uppercase;color:#ddd;font-weight:900}.console-big{font-size:3.5rem;font-weight:950;letter-spacing:-.08em;margin:.4rem 0;color:#fff}.console-line{display:flex;justify-content:space-between;border-top:1px solid rgba(255,255,255,.18);padding:.75rem 0;color:#eee}
.node-map{height:140px;margin-top:1rem;position:relative}.node{position:absolute;width:16px;height:16px;border-radius:50%;background:var(--glow);box-shadow:0 0 28px var(--glow)}.n1{left:18%;top:18%}.n2{left:68%;top:28%}.n3{left:42%;top:62%}.n4{left:82%;top:76%}.wire{position:absolute;height:2px;background:rgba(246,241,231,.55);transform-origin:left}.wire.a{width:155px;left:22%;top:28%;transform:rotate(12deg)}.wire.b{width:120px;left:45%;top:70%;transform:rotate(-24deg)}.wire.c{width:100px;left:22%;top:28%;transform:rotate(58deg)}
.marquee{white-space:nowrap;overflow:hidden;background:var(--ink);color:var(--paper);font-weight:950;letter-spacing:.12em;text-transform:uppercase;padding:.75rem 0}.marquee span{display:inline-block;animation:marquee 18s linear infinite}@keyframes marquee{from{transform:translateX(0)}to{transform:translateX(-50%)}}
.metric-card{border:2px solid var(--ink)!important;border-radius:24px!important;background:#fff!important;min-height:155px!important;box-shadow:8px 8px 0 var(--ink)!important;transition:transform .22s ease,box-shadow .22s ease}.metric-card:hover{transform:translate(-4px,-4px);box-shadow:13px 13px 0 var(--ink)!important}.metric-value{font-size:3rem!important}.section-title{display:flex!important;align-items:center;gap:.75rem}.section-title:before{content:"";width:46px;height:2.5px;background:var(--ink)}.panel{border:2px solid var(--ink)!important;border-radius:24px!important;background:var(--cream)!important;box-shadow:6px 6px 0 var(--ink)!important}.stButton>button,.stDownloadButton>button{box-shadow:5px 5px 0 var(--muted)!important}div[data-testid="stDataFrame"]{box-shadow:5px 5px 0 var(--ink)!important}
@media(max-width:950px){.hero-top{grid-template-columns:1fr}.hero-side{min-height:260px}.letter{font-size:clamp(3.1rem,14vw,5rem)}.block-container{padding-left:1rem!important;padding-right:1rem!important}}@media(prefers-reduced-motion:reduce){.letter,.marquee span{animation:none;transform:none;opacity:1;filter:none}}
</style>
"""


def premium_hero(version: str) -> str:
    line1 = animated_letters("Local network,", 0)
    line2 = animated_letters("clear signals.", 14)
    return f"""
    <div class="hero-shell">
        <div class="hero-top">
            <div class="hero-main">
                <div class="kicker">NetWatch / Local Defensive Visibility</div>
                <div class="hero-title-wrap"><span class="hero-line">{line1}</span><span class="hero-line">{line2}</span></div>
                <div class="hero-copy">A focused command room for host profiling, service checks, inventory, risk scoring, and clean reports on authorized local networks.</div>
                <div class="pill-row"><span class="pill dark">v{version}</span><span class="pill">Private IP Only</span><span class="pill">Risk Advisor</span><span class="pill">Safe Exports</span></div>
            </div>
            <div class="hero-side">
                <div class="console">
                    <div class="console-title">Live local signal</div><div class="console-big">READY</div>
                    <div class="console-line"><span>Mode</span><strong>Authorized</strong></div><div class="console-line"><span>Storage</span><strong>Local</strong></div><div class="console-line"><span>Reports</span><strong>Exportable</strong></div>
                    <div class="node-map"><div class="wire a"></div><div class="wire b"></div><div class="wire c"></div><div class="node n1"></div><div class="node n2"></div><div class="node n3"></div><div class="node n4"></div></div>
                </div>
            </div>
        </div>
        <div class="marquee"><span>SCAN / INSPECT / UNDERSTAND / EXPORT / LOCAL ONLY / NETWATCH / SCAN / INSPECT / UNDERSTAND / EXPORT / LOCAL ONLY / NETWATCH / </span></div>
    </div>
    """


def premium_sidebar() -> str:
    return """
    <div class="brand-card">
        <div class="brand-eyebrow">Control Room</div>
        <div class="brand-title">NetWatch</div>
        <div class="brand-sub">Local defensive dashboard</div>
    </div>
    """
