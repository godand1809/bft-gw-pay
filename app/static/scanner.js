/*
 * app/static/scanner.js -- Fare validator logic (VERSION 1.0.0)
 *
 * FLOW: camera decodes QR -> payload POSTed to /api/validate along with
 * route + scanner id -> server verifies HMAC signature, checks status,
 * expiry, and rides -> consume ride if valid -> accept/reject banner
 * shown and logged locally. Every validation is also stored in the
 * boardings table for analytics.
 */

const $ = (sel) => document.querySelector(sel);
let html5Scanner = null;

/** Show an accept/reject/info banner. */
function showBanner(kind, text) {
  const el = $("#scan-result");
  el.style.display = "block";
  el.className = "banner " + kind;   // "accept" | "reject" | "info"
  el.textContent = text;
}

/** Append a row to the local validation log table. */
function logRow(result, reason) {
  const tr = document.createElement("tr");
  const badge = result === "accepted" ? "accepted" : "rejected";
  tr.innerHTML = `<td>${new Date().toLocaleTimeString()}</td>
                  <td><span class="badge ${badge}">${result}</span></td>
                  <td>${reason}</td>`;
  $("#log-rows").prepend(tr);
}

/** POST the payload to the server and render the verdict. */
async function validate(payload) {
  try {
    const res = await fetch("/api/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        payload,
        route_id: $("#route").value,
        scanner_id: $("#scanner-id").value || "SCN-000",
        stop_code: $("#stop").value || null,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    if (data.result === "accepted") {
      const rides = data.rides_remaining === null
        ? "unlimited" : `${data.rides_remaining} rides left`;
      showBanner("accept", `✅ ACCEPTED — ${data.product_name} · ${rides} · rider ${data.rider_ref}`);
    } else {
      showBanner("reject", `❌ REJECTED — ${data.reason}`);
    }
    logRow(data.result, data.reason || data.detail || "error");
  } catch (e) {
    showBanner("reject", `❌ ERROR — ${e.message}`);
    logRow("rejected", e.message);
  }
}

/* ---------------- Camera (html5-qrcode) ---------------- */
$("#btn-start").addEventListener("click", () => {
  html5Scanner = new Html5Qrcode("qr-reader");
  html5Scanner.start(
    { facingMode: "environment" },           // rear camera on phones
    { fps: 10, qrbox: { width: 240, height: 240 } },
    (decodedText) => {
      // Debounce: stop after one successful read; operator taps Start again.
      html5Scanner.stop().then(() => validate(decodedText));
    },
    () => {} /* per-frame decode errors are noise; ignore */
  ).catch((err) => showBanner("reject", "Camera error: " + err));
});

$("#btn-stop").addEventListener("click", () => {
  if (html5Scanner) {
    html5Scanner.stop().catch(() => {});
    html5Scanner = null;
    showBanner("info", "Camera stopped.");
  }
});

/* ---------------- Manual entry ---------------- */
$("#btn-validate").addEventListener("click", () => {
  const payload = $("#payload").value.trim();
  if (payload) validate(payload);
});

/* ---------------- Populate selects + poster generator ---------------- */
(async function init() {
  const cat = await fetch("/api/catalog").then((r) => r.json());
  cat.routes.forEach((r) => {
    $("#route").insertAdjacentHTML("beforeend", `<option value="${r.id}">${r.id} — ${r.name}</option>`);
  });
  cat.stops.forEach((s) => {
    $("#stop").insertAdjacentHTML("beforeend", `<option value="${s.code}">${s.code} — ${s.name}</option>`);
    $("#poster-stop").insertAdjacentHTML("beforeend", `<option value="${s.code}">${s.code} — ${s.name}</option>`);
  });
})();

$("#btn-poster").addEventListener("click", () => {
  const code = $("#poster-stop").value;
  if (!code) return;
  $("#poster-out").innerHTML =
    `<img src="/api/stop/${encodeURIComponent(code)}/qr" alt="Stop QR" width="220" height="220"
          style="border:1px solid var(--border);border-radius:8px">`;
});
