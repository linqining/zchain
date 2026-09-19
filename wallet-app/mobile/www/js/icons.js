/* ZChain Wallet mobile — 线性图标精灵(38 枚,单线/方头/1.6 stroke)
 * 与 design/zchain-wallet-ui-b-ledger.html 的 <defs> 逐字节同源;
 * 另含品牌 logo(圆角方框 + Z + 旋方块)与 29 格收款码版式 qr-art。 */
"use strict";

(function mountSprite() {
  const SPRITE = `
<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
<symbol id="i-back" viewBox="0 0 24 24"><path d="M15 5 8 12l7 7"/></symbol>
<symbol id="i-chev-d" viewBox="0 0 24 24"><path d="M5 9l7 7 7-7"/></symbol>
<symbol id="i-chev-r" viewBox="0 0 24 24"><path d="M9 5l7 7-7 7"/></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><rect x="4" y="7" width="12" height="13"/><path d="M8 7V4h12v13h-4"/></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></symbol>
<symbol id="i-unlock" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9"/><path d="M8 11V8a4 4 0 0 1 7.5-2"/></symbol>
<symbol id="i-eye" viewBox="0 0 24 24"><path d="M2 12s4-6.5 10-6.5S22 12 22 12s-4 6.5-10 6.5S2 12 2 12z"/><circle cx="12" cy="12" r="2.6"/></symbol>
<symbol id="i-gear" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3.2"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/></symbol>
<symbol id="i-warn" viewBox="0 0 24 24"><path d="M12 3 21 20H3z"/><path d="M12 9v5M12 17h.01"/></symbol>
<symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 8h.01"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><path d="M4 12l5 5L20 6"/></symbol>
<symbol id="i-x" viewBox="0 0 24 24"><path d="M5 5l14 14M19 5L5 19"/></symbol>
<symbol id="i-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5.5l4 2"/></symbol>
<symbol id="i-refresh" viewBox="0 0 24 24"><path d="M20 12a8 8 0 1 1-2.9-6.2"/><path d="M20 4v5h-5"/></symbol>
<symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-3.5 8.2-8 9.2C7.5 20.2 4 17 4 12V6z"/><path d="M8.5 12l2.5 2.5 4.5-4.5"/></symbol>
<symbol id="i-key" viewBox="0 0 24 24"><circle cx="7.5" cy="12" r="4"/><path d="M11.5 12H21M17.5 12v3.5M14.5 12v2.5"/></symbol>
<symbol id="i-qr" viewBox="0 0 24 24"><rect x="4" y="4" width="6" height="6"/><rect x="14" y="4" width="6" height="6"/><rect x="4" y="14" width="6" height="6"/><path d="M14 14h2.5v2.5H14zM19 14h1.5M14 19h2.5M19 18.5v1.5"/></symbol>
<symbol id="i-send" viewBox="0 0 24 24"><path d="M4 12h13M13 6l6 6-6 6"/></symbol>
<symbol id="i-recv" viewBox="0 0 24 24"><path d="M20 12H7M11 6l-6 6 6 6"/></symbol>
<symbol id="i-out" viewBox="0 0 24 24"><path d="M12 4v11M8 11l4 4 4-4M4 20h16"/></symbol>
<symbol id="i-ul" viewBox="0 0 24 24"><path d="M12 20V8M8 12l4-4 4 4M4 4h16"/></symbol>
<symbol id="i-dl" viewBox="0 0 24 24"><path d="M12 4v12M8 12l4 4 4-4M4 20h16"/></symbol>
<symbol id="i-receipt" viewBox="0 0 24 24"><path d="M6 3h12v18l-3-2-3 2-3-2-3 2z"/><path d="M9 8h6M9 12h6"/></symbol>
<symbol id="i-wallet" viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="13"/><path d="M3 10.5h18M16 15h2"/></symbol>
<symbol id="i-spade" viewBox="0 0 24 24"><path d="M12 3.5C12 3.5 5 9.5 5 13.2a3.7 3.7 0 0 0 6.2 2.7L10.6 20.5h2.8L12.8 15.9A3.7 3.7 0 0 0 19 13.2C19 9.5 12 3.5 12 3.5Z"/></symbol>
<symbol id="i-ether" viewBox="0 0 24 24"><path d="M12 3 4.5 12.5 12 16.6 19.5 12.5Z"/><path d="M4.5 14.2 12 21.2l7.5-7L12 17.7Z"/></symbol>
<symbol id="i-layers" viewBox="0 0 24 24"><path d="M12 3 3 8l9 5 9-5z"/><path d="M3 12.6l9 5 9-5M3 17l9 5 9-5"/></symbol>
<symbol id="i-file" viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/></symbol>
<symbol id="i-swap" viewBox="0 0 24 24"><path d="M4 8h13M14 5l3 3-3 3M20 16H7M10 13l-3 3 3 3"/></symbol>
<symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
<symbol id="i-trash" viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M6.5 7 7.5 21h9l1-14"/></symbol>
<symbol id="i-ext" viewBox="0 0 24 24"><path d="M14 4h6v6M20 4l-8 8"/><path d="M18 13v7H4V6h7"/></symbol>
<symbol id="i-flask" viewBox="0 0 24 24"><path d="M9 3h6M10 3v6L5 20h14L14 9V3"/><path d="M7.6 15h8.8"/></symbol>
<symbol id="i-search" viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6"/><path d="M15 15l5 5"/></symbol>
<symbol id="i-book" viewBox="0 0 24 24"><path d="M4 4h6.5A1.5 1.5 0 0 1 12 5.5V20a2 2 0 0 0-2-2H4z"/><path d="M20 4h-6.5A1.5 1.5 0 0 0 12 5.5V20a2 2 0 0 1 2-2h6z"/></symbol>
<symbol id="i-home" viewBox="0 0 24 24"><path d="M4 11 12 4l8 7v9H4z"/><path d="M10 20v-6h4v6"/></symbol>
<symbol id="i-pen" viewBox="0 0 24 24"><path d="M4 20l1.2-4.2L16 5l3 3L8.2 18.8z"/></symbol>
<symbol id="i-bolt" viewBox="0 0 24 24"><path d="M13 3 5 14h6l-1 7 8-11h-6z"/></symbol>
</defs>
<symbol id="logo-zc" viewBox="0 0 64 64"><rect x="2" y="2" width="60" height="60" rx="14" fill="none" stroke="currentColor" stroke-width="4"/><path d="M17 21 H45 L24 43 H47" fill="none" stroke="currentColor" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/><rect x="42" y="8" width="9" height="9" rx="1.5" transform="rotate(45 46.5 12.5)" fill="currentColor"/></symbol>
<symbol id="qr-art" viewBox="0 0 29 29" shape-rendering="crispEdges"><rect width="29" height="29" fill="#fff"/><g fill="#14130f"><path d="M0 0h7v7H0zM22 0h7v7h-7zM0 22h7v7H0z"/><path d="M2 2h3v3H2zM24 2h3v3h-3zM2 24h3v3H2z" fill="#fff"/><path d="M9 0h2v2H9zM13 0h2v3h-2zM17 0h2v2h-2zM9 4h2v2H9zM12 4h2v2h-2zM16 4h3v2h-3zM20 4h1v2h-1zM0 9h2v2H0zM4 9h3v2H4zM9 9h3v3H9zM14 9h2v2h-2zM18 9h2v2h-2zM22 9h3v2h-3zM26 9h3v2h-3zM2 13h2v2H2zM7 13h2v2H7zM11 13h3v2h-3zM16 13h2v3h-2zM20 13h2v2h-2zM24 13h2v2h-2zM0 17h3v2H0zM5 17h2v2H5zM9 17h2v2H9zM13 17h3v2h-3zM18 17h2v2h-2zM22 17h2v2h-2zM26 17h3v2h-3zM2 21h2v2H2zM6 21h3v2H6zM11 21h2v2h-2zM15 21h2v2h-2zM19 21h3v2h-3zM23 21h2v2h-2zM27 21h2v3h-2zM9 25h3v2H9zM14 25h2v2h-2zM18 25h3v2h-3zM23 25h2v4h-2zM26 26h3v3h-3z"/></g></symbol>
</svg>`;
  document.addEventListener("DOMContentLoaded", () => {
    document.body.insertAdjacentHTML("afterbegin", SPRITE);
  });
})();
