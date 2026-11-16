/*
 * app/static/dashboard.js -- Analytics dashboard logic (VERSION 1.0.0)
 *
 * FLOW: choose a range (7/30/90 days) -> GET /api/admin/analytics?days=N
 * -> render KPI tiles, four Chart.js charts, and the recent-activity
 * tables. Rider emails are masked server-side (xxx***@domain) and the
 * CSV export uses R-<sha1> references, never raw emails.
 */

const $ = (sel) => document.querySelector(sel);
const money = (cents) => "$" + (cents / 100).toFixed(2);
const charts = {};   // keep Chart.js instances so we can destroy on reload

/** Render the 6 KPI tiles from the analytics payload. */
function renderKpis(k) {
  const tiles = [
    { label: "Revenue", value: money(k.revenue_cents), cls: "" },
    { label: "Boardings", value: k.boardings.toLocaleString(), cls: "green" },
    { label: "Accepted", value: k.accepted.toLocaleString(), cls: "green" },
    { label: "Rejected", value: k.rejected.toLocaleString(), cls: "danger" },
    { label: "Active tickets", value: k.active_tickets.toLocaleString(), cls: "yellow" },
    { label: "Accounts", value: k.accounts.toLocaleString(), cls: "" },
  ];
  $("#kpis").innerHTML = tiles.map((t) => `
    <div class="kpi ${t.cls}">
      <div class="label">${t.label}</div>
      <div class="value">${t.value}</div>
    </div>`).join("");
}

/** Create or replace a named chart. */
function makeChart(id, config) {
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart($(id), config);
}

/** Load analytics for the selected range and paint everything. */
async function load() {
  const days = $("#range").value;
  const d = await fetch(`/api/admin/analytics?days=${days}`).then((r) => r.json());
  renderKpis(d.kpis);

  // Line chart: revenue per day.
  makeChart("#chart-revenue", {
    type: "line",
    data: {
      labels: d.revenue_by_day.map((r) => r.day.slice(5)),
      datasets: [{
        label: "Revenue ($)",
        data: d.revenue_by_day.map((r) => r.cents / 100),
        borderColor: "#00539b",
        backgroundColor: "rgba(0,83,155,0.12)",
        fill: true,
        tension: 0.3,
      }],
    },
    options: { plugins: { legend: { display: false } } },
  });

  // Bar chart: boardings per route (uses each route's brand color).
  makeChart("#chart-routes", {
    type: "bar",
    data: {
      labels: d.rides_by_route.map((r) => r.route),
      datasets: [{
        label: "Boardings",
        data: d.rides_by_route.map((r) => r.boardings),
        backgroundColor: d.rides_by_route.map((r) => r.color),
      }],
    },
    options: { plugins: { legend: { display: false } } },
  });

  // Doughnut: revenue share by fare product.
  makeChart("#chart-products", {
    type: "doughnut",
    data: {
      labels: d.product_breakdown.map((r) => r.product),
      datasets: [{
        data: d.product_breakdown.map((r) => r.cents / 100),
        backgroundColor: ["#00539b", "#00843d", "#ffb500", "#6a3d9a", "#c0392b"],
      }],
    },
  });

  // Doughnut: wallet vs card payment mix.
  makeChart("#chart-methods", {
    type: "doughnut",
    data: {
      labels: d.revenue_by_method.map((r) => r.method),
      datasets: [{
        data: d.revenue_by_method.map((r) => r.cents / 100),
        backgroundColor: ["#00539b", "#ffb500"],
      }],
    },
  });

  // Recent transactions (rider email masked server-side).
  $("#tx-rows").innerHTML = d.recent_transactions.map((t) => `
    <tr>
      <td>${t.id}</td>
      <td><span class="badge ${t.type}">${t.type}</span></td>
      <td>${money(t.amount_cents)}</td>
      <td>${t.email}</td>
      <td>${new Date(t.created_at).toLocaleString()}</td>
    </tr>`).join("");

  // Recent validations (accepted/rejected scans).
  $("#val-rows").innerHTML = d.recent_validations.map((v) => `
    <tr>
      <td>${new Date(v.scanned_at).toLocaleString()}</td>
      <td>${v.route_id}</td>
      <td><span class="badge ${v.result}">${v.result}</span></td>
      <td>${v.reason}</td>
      <td>${v.scanner_id}</td>
    </tr>`).join("");
}

$("#range").addEventListener("change", load);
load();
