#!/usr/bin/env python3
"""客户端设计稿出图：design/client/zchain-client-ui.html → design/client/png/<ground>--<id>.png

为什么走 HTTP 而不是 file://：探针页要读 iframe 的 contentDocument，
file:// 下浏览器按跨源处理，读不到高度只会静默回退默认值。

用法：
  python3 design/client/render.py            # 纸白全套
  GROUND=night python3 design/client/render.py
  python3 design/client/render.py c2 c7      # 只出指定屏
"""
import json
import os
import re
import subprocess
import sys
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
DESIGN = HERE.parent                       # design/
SRC = "client/zchain-client-ui.html"
IDS = ["c1", "c2", "c3", "c4", "c5", "c6", "c7"]
PORT = int(os.environ.get("PORT", "8790"))
BASE = f"http://127.0.0.1:{PORT}"
GROUND = os.environ.get("GROUND", "paper")


def find_chrome() -> str:
    env = os.environ.get("ZCHAIN_CFT_CHROME")
    if env:
        return env
    import glob
    hits = glob.glob("/tmp/chrome/**/Google Chrome for Testing", recursive=True)
    if hits:
        return hits[0]
    sys.exit("Chrome for Testing 未找到；请设置 ZCHAIN_CFT_CHROME")


def probe_heights(chrome: str, ids: list[str], ground: str) -> dict[str, int]:
    frames = "".join(
        f'<iframe data-id="{i}" src="/{SRC}?g={ground}&shot=1#{i}"></iframe>'
        for i in ids
    )
    js = r'''
window.addEventListener("load",function(){setTimeout(function(){
  var out={};
  Array.prototype.forEach.call(document.querySelectorAll("iframe"),function(fr){
    try{
      var d=fr.contentDocument;
      var s=d.querySelector("#shot-mount .screen");
      out[fr.dataset.id]=s?s.getBoundingClientRect().height:d.body.scrollHeight;
    }catch(e){out[fr.dataset.id]=0}
  });
  var o=document.createElement("div");o.id="__h";o.textContent=JSON.stringify(out);
  document.body.appendChild(o);
},1800)});
'''
    probe = ("<!DOCTYPE html><meta charset=\"utf-8\"><body style=\"margin:0\">"
             "<style>iframe{display:block;width:1280px;height:1200px;border:0}</style>"
             + frames + "<script>" + js + "</script></body>")
    (DESIGN / "__probe.html").write_text(probe, encoding="utf-8")
    try:
        html = subprocess.run(
            [chrome, "--headless", "--disable-gpu", "--hide-scrollbars",
             "--window-size=1320,1000", "--virtual-time-budget=15000",
             "--dump-dom", f"{BASE}/__probe.html"],
            capture_output=True, text=True, timeout=180).stdout
    finally:
        (DESIGN / "__probe.html").unlink(missing_ok=True)

    m = re.search(r'<div id="__h">(.*?)</div>', html, re.S)
    if not m:
        print("  ! 探针未返回高度", file=sys.stderr)
        return {}
    raw = json.loads(m.group(1).replace("&quot;", '"').replace("&amp;", "&"))
    return {k: min(max(int(v or 0) + 2, 400), 6000) for k, v in raw.items()}


def main() -> int:
    ids = sys.argv[1:] or IDS
    out = HERE / "png"
    out.mkdir(exist_ok=True)
    handler = partial(SimpleHTTPRequestHandler, directory=str(DESIGN))
    handler.log_message = lambda *a, **k: None
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    chrome = find_chrome()
    try:
        hs = probe_heights(chrome, ids, GROUND)
        for i in ids:
            h = hs.get(i, 900)
            f = out / f"{GROUND}--{i}.png"
            subprocess.run(
                [chrome, "--headless", "--disable-gpu", "--hide-scrollbars",
                 f"--window-size=1280,{h}", "--virtual-time-budget=4000",
                 f"--screenshot={f}",
                 f"{BASE}/{SRC}?g={GROUND}&shot=1#{i}"],
                capture_output=True, text=True, timeout=120)
            print(f"  {GROUND} {i}  {h}px  → {f.name}")
    finally:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
