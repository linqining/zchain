#!/usr/bin/env python3
"""生成全站设计稿评审台：design/review/index.html + design/review/thumbs/*.jpg

为什么不直接把 PNG 塞进 HTML：41 + 13 + 12 + 14 张整页 PNG 合计 30MB+，
一次加载会把评审页变成下载页。缩略图统一压到 320px 宽 JPEG，
点卡片才打开原始 PNG。

用法：python3 design/review/build.py
"""
import json
import re
import pathlib
from PIL import Image

ROOT = pathlib.Path(__file__).resolve().parents[2]      # 仓库根
DESIGN = ROOT / "design"
OUT = DESIGN / "review"
TH = OUT / "thumbs"
WEB_DIST = ROOT / "website" / "dist"


def title_of(slug: str) -> str:
    """从构建产物里取真实 <title>，评审台不另编一套页名。"""
    rel = "index.html" if slug == "home" else slug.replace("-", "/") + "/index.html"
    f = WEB_DIST / rel
    if not f.exists():
        # docs 的 slug 用 - 连接，但 abi 这类原本就有层级
        for cand in WEB_DIST.rglob("index.html"):
            if cand.parent.relative_to(WEB_DIST).as_posix().replace("/", "-") == slug:
                f = cand
                break
    if not f.exists():
        return slug
    m = re.search(r"<title>(.*?)</title>", f.read_text(encoding="utf-8"), re.S)
    return (m.group(1).strip() if m else slug).split(" · ")[0]


def thumb(src: pathlib.Path, key: str) -> tuple[str, int, int]:
    TH.mkdir(parents=True, exist_ok=True)
    dst = TH / f"{key}.jpg"
    with Image.open(src) as im:
        w, h = im.size
        scale = 320 / w
        im.convert("RGB").resize((320, max(1, int(h * scale))), Image.LANCZOS).save(
            dst, "JPEG", quality=72, optimize=True)
    return dst.name, w, h


def collect():
    groups = []

    # ---- 体系板 ----
    items = []
    for g in ("paper", "night"):
        p = DESIGN / "site" / "png" / f"board-{g}.png"
        if p.exists():
            n, w, h = thumb(p, f"board-{g}")
            items.append(dict(key=f"board-{g}", label="站点体系板 S0–S10（桌面）",
                              sub=f"website/assets/css/main.css · {g}", w=w, h=h,
                              full=f"../site/png/board-{g}.png", thumb=n, kind="board"))
        mp = DESIGN / "site" / "png" / f"mobile-board-{g}.png"
        if mp.exists():
            n, w, h = thumb(mp, f"mobile-board-{g}")
            items.append(dict(key=f"mobile-board-{g}", label="站点体系板 M0–M6（移动 390）",
                              sub=f"main.css + ledger-mobile.css · {g}", w=w, h=h,
                              full=f"../site/png/mobile-board-{g}.png", thumb=n, kind="board"))
    groups.append(dict(id="system", title="设计体系",
                       desc="token、组件与类名还原度基准；移动板验的是叠加层生效后的真实排版",
                       items=items))

    # ---- 牌桌 ----
    titems = []
    meta = {
        "t1": "T1 空桌 · 待入座", "t2": "T2 对局中 · 他人行动", "t3": "T3 轮到我行动",
        "t4": "T4 摊牌与派彩", "t5": "T5 买入弹窗", "t6": "T6 本手凭证",
        "g1": "G1 展示桌主视图", "g2": "G2 证明面板", "ds": "DS 牌桌组件板",
    }
    for p in sorted((DESIGN / "table" / "png").glob("*.png")):
        ground, sid = p.stem.split("--", 1)
        n, w, h = thumb(p, f"table-{p.stem}")
        titems.append(dict(key=f"table-{p.stem}", label=meta.get(sid, sid),
                           sub=f"{ground} · {w}×{h}", w=w, h=h,
                           full=f"../table/png/{p.name}", thumb=n, kind="table"))
    rank = {k: i for i, k in enumerate(meta)}
    titems.sort(key=lambda d: (0 if "paper" in d["key"] else 1, rank.get(d["key"].split("--")[-1], 99)))
    groups.append(dict(id="table", title="牌桌 /play 与 /game/:id",
                       desc="9 屏 × 纸白/夜场 · 已评审通过", items=titems))

    # ---- 客户端 ----
    cmeta = {
        "c1": ("C1 首页", "/"), "c2": ("C2 大厅", "/lobby"), "c3": ("C3 个人中心", "/dashboard"),
        "c4": ("C4 白皮书", "/whitepaper"), "c5": ("C5 未找到", "/*"),
        "c6": ("C6 登录弹窗", "modal"), "c7": ("C7 领取奖励", "modal"),
    }
    citems = []
    for p in sorted((DESIGN / "client" / "png").glob("*.png")):
        ground, cid = p.stem.split("--", 1)
        n, w, h = thumb(p, f"client-{p.stem}")
        lab, rt = cmeta.get(cid, (cid, ""))
        citems.append(dict(key=f"client-{p.stem}", label=lab, sub=f"{rt} · {ground} · {w}×{h}",
                           w=w, h=h, full=f"../client/png/{p.name}", thumb=n, kind="client"))
    citems.sort(key=lambda d: (d["label"], 0 if "paper" in d["key"] else 1))
    groups.append(dict(id="client", title="客户端其余页面",
                       desc="React 路由 7 屏 · 文案取自 zh.json 原文", items=citems))

    # ---- 站点逐页 ----
    sitems = []
    desk = DESIGN / "site" / "pages" / "desktop"
    for p in sorted(desk.glob("*.png")):
        n, w, h = thumb(p, f"site-{p.stem}")
        sitems.append(dict(key=f"site-{p.stem}", label=title_of(p.stem),
                           sub=f"/{p.stem.replace('-', '/')}/".replace("//", "/") if p.stem != "home" else "/",
                           w=w, h=h, full=f"../site/pages/desktop/{p.name}", thumb=n, kind="site"))
    groups.append(dict(id="site-desk", title="站点逐页 · 桌面 1280",
                       desc=f"{len(sitems)} 页 · 纸白底 · 真实构建产物直接换 CSS", items=sitems))

    nitems = []
    for p in sorted((DESIGN / "site" / "pages" / "desktop-night").glob("*.png")):
        n, w, h = thumb(p, f"siten-{p.stem}")
        nitems.append(dict(key=f"siten-{p.stem}", label=title_of(p.stem),
                           sub=f"夜场底 · {w}×{h}", w=w, h=h,
                           full=f"../site/pages/desktop-night/{p.name}", thumb=n, kind="site"))
    groups.append(dict(id="site-night", title="站点逐页 · 夜场底",
                       desc=f"{len(nitems)} 顶层页 · docs 与纸白同构不重复出图", items=nitems))

    MOBILE_GROUPS = [
        ("mobile", "site-mob", "站点逐页 · 移动 390",
         "chip 轨导航 + 凭证行卡 + docs 小节轨 · deviceScaleFactor 2"),
        ("mobile-night", "site-mobn", "站点逐页 · 移动夜场",
         "13 顶层页 · docs 与纸白同构不重复出图"),
        ("mobile-360", "site-m360", "档位抽查 · 360px",
         "explorer / home / ABI 三页，验最窄常见档"),
        ("mobile-430", "site-m430", "档位抽查 · 430px",
         "同上，验大屏不出现空洞与异常换行"),
    ]
    for d, gid, title, desc in MOBILE_GROUPS:
        dirp = DESIGN / "site" / "pages" / d
        if not dirp.exists():
            continue
        items = []
        for p in sorted(dirp.glob("*.png")):
            n, w, h = thumb(p, f"{gid}-{p.stem}")
            items.append(dict(key=f"{gid}-{p.stem}", label=title_of(p.stem),
                              sub=f"{d} · {w}×{h}", w=w, h=h,
                              full=f"../site/pages/{d}/{p.name}", thumb=n, kind="site"))
        if items:
            groups.append(dict(id=gid, title=title, desc=f"{len(items)} 张 · {desc}", items=items))

    return groups


HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZChain Poker · 账簿设计稿评审台</title>
<style>
:root{--pg:#f5f2ea;--cd:#fffdf7;--ink:#14130f;--ink2:#4b4840;--ink3:#666256;
--rl:#ddd6c6;--rl2:#c3bba7;--felt:#0b6b45;--feltw:#e6efe8;--code:#efeade;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--ui:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
html[data-g=night]{--pg:#070d0a;--cd:#101c15;--ink:#f0f7f1;--ink2:#abc3b6;--ink3:#7d9a8b;
--rl:#1d3326;--rl2:#2a4a37;--felt:#37e39c;--feltw:rgba(55,227,156,.11);--code:#0a120d}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--pg);color:var(--ink);font-family:var(--ui);font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}
.hd{position:sticky;top:0;z-index:20;background:var(--cd);border-bottom:1px solid var(--rl2);padding:14px 24px}
.hd .r1{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.hd h1{font-size:17px;font-weight:800;letter-spacing:-.015em}
.hd .n{font-family:var(--mono);font-size:10.5px;color:var(--ink3);letter-spacing:.06em}
.hd .sp{flex:1}
.tg{display:flex;gap:6px}
.tg button{border:1px solid var(--rl2);background:var(--pg);color:var(--ink2);border-radius:3px;
padding:4px 10px;font-family:var(--mono);font-size:10.5px;letter-spacing:.08em;cursor:pointer}
.tg button[aria-pressed=true]{background:var(--ink);color:var(--pg);border-color:var(--ink)}
nav.jump{display:flex;gap:4px;flex-wrap:wrap;margin-top:11px}
nav.jump a{font-family:var(--mono);font-size:10.5px;letter-spacing:.06em;color:var(--ink3);
border:1px solid var(--rl);border-radius:3px;padding:3px 8px;text-decoration:none}
nav.jump a:hover{color:var(--felt);border-color:var(--felt)}
main{max-width:1400px;margin:0 auto;padding:26px 24px 70px}
section{margin-bottom:40px;scroll-margin-top:120px}
.sh{display:flex;align-items:baseline;gap:12px;border-bottom:1px solid var(--ink);padding-bottom:7px;margin-bottom:5px}
.sh h2{font-size:16px;font-weight:800;letter-spacing:-.01em}
.sh .c{font-family:var(--mono);font-size:10.5px;color:var(--ink3);letter-spacing:.08em}
.sd{font-size:12.5px;color:var(--ink3);margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(216px,1fr));gap:14px}
a.card{display:block;background:var(--cd);border:1px solid var(--rl2);border-radius:5px;
text-decoration:none;color:inherit;overflow:hidden}
a.card:hover{border-color:var(--felt);box-shadow:0 0 0 1px var(--felt) inset}
.frame{position:relative;height:250px;overflow:hidden;background:var(--code);border-bottom:1px solid var(--rl)}
.frame img{position:absolute;top:0;left:0;width:100%;height:auto;display:block}
.frame .full{position:static;width:100%;height:100%;object-fit:cover;object-position:top left}
.cap{padding:9px 11px 11px}
.cap .t{font-size:13px;font-weight:700;line-height:1.35}
.cap .s{font-family:var(--mono);font-size:10px;color:var(--ink3);margin-top:4px;letter-spacing:.04em;word-break:break-all}
.tag{position:absolute;top:8px;left:8px;font-family:var(--mono);font-size:9px;font-weight:700;
letter-spacing:.1em;background:var(--ink);color:var(--pg);padding:2px 6px;border-radius:2px}
.big{background:var(--cd);border:1px solid var(--rl2);border-radius:5px;overflow:hidden}
.big img{display:block;width:100%}
footer{max-width:1400px;margin:0 auto;padding:0 24px 50px;font-size:12px;color:var(--ink3);line-height:1.8}
footer code{font-family:var(--mono);background:var(--code);padding:1px 5px;border-radius:2px;font-size:11.5px}
</style></head><body>
<div class="hd">
  <div class="r1">
    <h1>ZChain Poker · 账簿 Ledger 设计稿评审台</h1>
    <span class="n">__COUNTS__</span><span class="n" style="opacity:.62">（右上只切评审台自身底色；每张图是什么底写在卡片副标题里）</span>
    <span class="sp"></span>
    <div class="tg"><button data-g="paper" aria-pressed="true">本页底纸 · 纸白</button>
      <button data-g="night" aria-pressed="false">本页底纸 · 夜场</button></div>
  </div>
  <nav class="jump">__JUMP__</nav>
</div>
<main>__BODY__</main>
<footer>
  <p><b>怎么读这套稿</b>：体系板是基准（桌面 S0–S10 / 移动 M0–M6）；牌桌稿 T1–T6/G1–G2 已评审通过；
  客户端 C1–C7 是新增；站点 41 页是<b>真实构建产物</b>逐页出的图，不是重画的假页面 ——
  文案、表格、数字与线上一致，可以直接当还原度验收依据。
  账簿主样式已落地为 <code>website/assets/css/main.css</code>；
  移动层 <code>design/site/ledger-mobile.css</code> 仍是<b>待落地的增量层</b>，出图时叠在副本上。</p>
  <p><b>重跑</b>：桌面 <code>python3 website/build.py && python3 website/tools/cdp_shoot.py</code>
  （加 <code>GROUND=night TOPLEVEL=1</code> 出夜场；本机 headless Chrome 已不可用，
  两个 shooter 都走有头实例 + CDP）；
  移动 <code>python3 website/build.py && MOBILE=1 python3 website/tools/cdp_shoot.py</code>
  （加 <code>GROUND=night TOPLEVEL=1</code> 或 <code>VW=360,430 SLUGS=…</code>）；
  体系板 <code>BOARD="design/site/zchain-site-mobile-ui.html:mobile-board" python3 website/tools/cdp_shoot.py</code>；
  移动走查 <code>python3 website/tools/audit_mobile.py</code>；
  客户端 <code>python3 design/client/render.py</code>；牌桌 <code>bash design/table/render.sh</code>。
  最后 <code>python3 design/review/build.py</code> 刷新本页。</p>
  <p><b>已知未达项</b>见 <code>design/site/README.md</code>（含移动段与落地补丁）与 <code>design/client/README.md</code>。</p>
</footer>
<script>
document.querySelectorAll('[data-g]').forEach(function(b){b.addEventListener('click',function(){
  document.documentElement.setAttribute('data-g',b.dataset.g);
  document.querySelectorAll('[data-g]').forEach(function(o){o.setAttribute('aria-pressed',String(o===b))});
})});
</script></body></html>
"""


def guard_duplicates() -> list[str]:
    """夜场图若与纸白图逐字节相同，说明 data-ground 没生效——直接报错而不是出假图。"""
    import hashlib
    bad = []
    pairs = [(DESIGN / "site" / "pages" / "desktop", DESIGN / "site" / "pages" / "desktop-night"),
             (DESIGN / "site" / "pages" / "mobile", DESIGN / "site" / "pages" / "mobile-night")]
    for paper, night in pairs:
        if not night.exists():
            continue
        for np in night.glob("*.png"):
            pp = paper / np.name
            if not pp.exists():
                continue
            if hashlib.md5(pp.read_bytes()).digest() == hashlib.md5(np.read_bytes()).digest():
                bad.append(np.name)
    if bad:
        raise SystemExit(
            f"夜场图与纸白图完全相同（{len(bad)} 张：{', '.join(bad[:4])} …）。\n"
            "原因几乎一定是 dist 的 <html> 缺 data-ground=\"night\"；"
            "用 GROUND=night python3 website/tools/site_shoot.py 重出。")
    return bad


def main() -> int:
    guard_duplicates()
    groups = collect()
    total = sum(len(g["items"]) for g in groups)
    body = []
    for g in groups:
        cards = []
        for it in g["items"]:
            cards.append(
                f'<a class="card" href="{it["full"]}" target="_blank" rel="noopener">'
                f'<div class="frame"><span class="tag">{it["key"].split("-")[0].upper()}</span>'
                f'<img class="full" loading="lazy" src="thumbs/{it["thumb"]}" alt="{it["label"]}"></div>'
                f'<div class="cap"><div class="t">{it["label"]}</div>'
                f'<div class="s">{it["sub"]} · {it["w"]}×{it["h"]}</div></div></a>')
        body.append(f'<section id="{g["id"]}"><div class="sh"><h2>{g["title"]}</h2>'
                    f'<span class="c">{len(g["items"])} 张</span></div>'
                    f'<p class="sd">{g["desc"]}</p><div class="grid">{"".join(cards)}</div></section>')
    jump = "".join(f'<a href="#{g["id"]}">{g["title"]}</a>' for g in groups)
    counts = " · ".join(f'{g["title"]} {len(g["items"])}' for g in groups)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "index.html").write_text(
        HTML.replace("__BODY__", "".join(body)).replace("__JUMP__", jump).replace("__COUNTS__", counts),
        encoding="utf-8")
    print(f"评审台 → design/review/index.html（{total} 张，缩略图 {len(list(TH.glob('*.jpg')))} 个）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
