/*
 * app/static/app.js -- Rider app logic (VERSION 1.1.0)
 *
 * v1.1.0 SECURITY (refs: v1.0.0):
 *   - All dynamic values are HTML-escaped via esc() before being
 *     inserted with innerHTML (defense-in-depth XSS hardening; the
 *     backend is parameterized-SQL and catalog data is static, but
 *     we never trust serialized server data in the DOM anyway).
 *
 * FLOW: sign in -> (optional) top up wallet -> buy fare -> QR ticket
 * appears under "My Tickets" -> show QR to the scanner -> receipt
 * recorded automatically.
 *
 * All server calls go through the small api() wrapper below so
 * error handling and JSON parsing live in one place.
 */

const $ = (sel) => document.querySelector(sel);

/** HTML-escape a value for safe interpolation into innerHTML. */
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/** Fetch wrapper: JSON in/out, throws Error(message) on !ok. */
async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

const money = (cents) => "$" + (cents / 100).toFixed(2);
let selectedProduct = null;
let catalog = null;

/* ---------------- Tabs ---------------- */
document.querySelectorAll(".tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll("main section").forEach((s) => (s.style.display = "none"));
    document.getElementById("tab-" + btn.dataset.tab).style.display = "block";
  });
});

/* ---------------- Sign in / out ---------------- */
$("#btn-signin").addEventListener("click", async () => {
  const email = $("#email").value.trim();
  if (!email) return alert("Enter an email address");
  await api("/api/session", { method: "POST", body: JSON.stringify({ email }) });
  boot();
});

$("#btn-logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
  location.reload();
});

/* ---------------- Wallet top-up (simulated payment) ---------------- */
document.querySelectorAll(".amt").forEach((b) =>
  b.addEventListener("click", () => { $("#card-last4").focus(); b.dataset.picked = "1"; }));

$("#btn-topup").addEventListener("click", async () => {
  // Use the last clicked quick-amount, defaulting to $10.
  const picked = document.querySelector(".amt[data-picked]");
  const cents = picked ? parseInt(picked.dataset.amt) : 1000;
  const last4 = $("#card-last4").value.trim();
  if (!/^\d{4}$/.test(last4)) return alert("Enter the 4-digit card suffix");
  try {
    await api("/api/topup", {
      method: "POST",
      body: JSON.stringify({ amount_cents: cents, card_last4: last4 }),
    });
    boot();
  } catch (e) { alert(e.message); }
});

/* ---------------- Buy fare ---------------- */
function renderProducts() {
  const reduced = $("#reduced").checked;
  const grid = $("#product-grid");
  grid.innerHTML = "";
  catalog.products.forEach((p) => {
    const div = document.createElement("div");
    div.className = "product" + (selectedProduct === p.code ? " selected" : "");
    const price = reduced ? p.reduced_price_cents : p.price_cents;
    div.innerHTML = `
      <div class="p-name">${esc(p.name)}${p.mobile_only ? " 📱" : ""}</div>
      <div class="p-price">${money(price)}</div>
      <div class="p-desc">${esc(p.description)}</div>`;
    div.addEventListener("click", () => {
      selectedProduct = p.code;
      const btn = $("#btn-purchase");
      btn.disabled = false;
      btn.textContent = `Buy ${p.name} — ${money(price)}`;
      renderProducts();
    });
    grid.appendChild(div);
  });
}

$("#reduced").addEventListener("change", renderProducts);

$("#btn-purchase").addEventListener("click", async () => {
  if (!selectedProduct) return;
  try {
    const out = await api("/api/purchase", {
      method: "POST",
      body: JSON.stringify({ product_code: selectedProduct, reduced: $("#reduced").checked }),
    });
    alert(`Purchased! Receipt ${out.receipt_id}. Find your QR under "My Tickets".`);
    // Switch to the tickets tab so the new QR is immediately visible.
    document.querySelector('.tabs button[data-tab="tickets"]').click();
    boot();
  } catch (e) { alert(e.message); }
});

/* ---------------- My tickets ---------------- */
function renderTickets(tickets) {
  const list = $("#ticket-list");
  list.innerHTML = tickets.length ? "" : "<p style='color:var(--muted)'>No tickets yet — buy a fare first.</p>";
  tickets.forEach((t) => {
    const div = document.createElement("div");
    div.className = "ticket";
    const rides = t.rides_remaining === null ? "Unlimited" : `${t.rides_remaining} rides left`;
    div.innerHTML = `
      <img class="qr" src="${esc(t.qr_png_data_uri)}" alt="Ticket QR">
      <div class="info">
        <div class="name">${esc(t.product_name)}</div>
        <div class="meta">${esc(rides)} · expires ${esc(new Date(t.expires_at).toLocaleString())}</div>
        <span class="badge ${esc(t.status)}">${esc(t.status)}</span>
        <div class="payload">${esc(t.qr_payload)}</div>
      </div>`;
    list.appendChild(div);
  });
}

/* ---------------- Receipts ---------------- */
function renderReceipts(receipts) {
  const rows = $("#receipt-rows");
  rows.innerHTML = receipts.length ? "" : "<tr><td colspan='7' style='color:var(--muted)'>No receipts yet.</td></tr>";
  receipts.forEach((r) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(r.id)}</td>
      <td>${esc(new Date(r.created_at).toLocaleString())}</td>
      <td><span class="badge ${esc(r.type)}">${esc(r.type)}</span></td>
      <td>${esc(r.description)}</td>
      <td>${money(r.amount_cents)}</td>
      <td><span class="badge ${esc(r.status)}">${esc(r.status)}</span></td>
      <td><a class="btn" style="padding:4px 10px;font-size:12px" href="/static/receipt.html?id=${encodeURIComponent(r.id)}">View</a></td>`;
    rows.appendChild(tr);
  });
}

/* ---------------- Stop deep-link banner (?stop=CODE) ---------------- */
function handleStopParam(me) {
  const stop = new URLSearchParams(location.search).get("stop");
  if (!stop || !me.signed_in) return;
  fetch("/api/stop/" + encodeURIComponent(stop))
    .then((r) => (r.ok ? r.json() : null))
    .then((s) => {
      if (!s) return;
      const el = $("#stop-banner");
      el.style.display = "block";
      el.textContent = `You scanned the poster at ${s.name}. Buy a fare below, then board route of your choice.`;
      document.querySelector('.tabs button[data-tab="buy"]').click();
    });
}

/* ---------------- Boot ---------------- */
async function boot() {
  // Expire stale tickets server-side, then load everything.
  try {
    const me = await api("/api/me");
    if (!me.signed_in) {
      $("#signin").style.display = "block";
      $("#app").style.display = "none";
      return;
    }
    $("#signin").style.display = "none";
    $("#app").style.display = "block";
    $("#btn-logout").style.display = "inline-block";
    $("#user-email").textContent = me.email;
    $("#wallet-balance").textContent = money(me.wallet_cents);

    await api("/api/tickets/expire-sweep", { method: "POST" });
    if (!catalog) catalog = await api("/api/catalog");
    renderProducts();
    renderTickets((await api("/api/tickets")).tickets);
    renderReceipts((await api("/api/receipts")).receipts);
    handleStopParam(me);
  } catch (e) {
    console.error(e);
  }
}

boot();
