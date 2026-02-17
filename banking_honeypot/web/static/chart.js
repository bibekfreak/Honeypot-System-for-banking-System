let typesChart;

async function fetchJson(url) {
  const r = await fetch(url);
  return await r.json();
}

async function refresh() {
  const summary = await fetchJson("/api/summary");
  document.getElementById("total").innerText = summary.total_attacks;
  document.getElementById("unique").innerText = summary.unique_ips;
  document.getElementById("blocked").innerText = summary.blocked_ips;

  const types = await fetchJson("/api/attack_types");
  const labels = types.map(x => x.attack_type);
  const values = types.map(x => x.c);

  const ctx = document.getElementById("typesChart");
  if (!typesChart) {
    typesChart = new Chart(ctx, {
      type: "bar",
      data: { labels, datasets: [{ label: "Count", data: values }] },
      options: { responsive: true }
    });
  } else {
    typesChart.data.labels = labels;
    typesChart.data.datasets[0].data = values;
    typesChart.update();
  }

  const attackers = await fetchJson("/api/top_attackers");
  const tbodyA = document.querySelector("#topAttackers tbody");
  tbodyA.innerHTML = attackers.map(a => `<tr><td>${a.source_ip}</td><td>${a.c}</td></tr>`).join("");

  const recent = await fetchJson("/api/recent_attacks");
  const tbodyR = document.querySelector("#recentAttacks tbody");
  tbodyR.innerHTML = recent.map(r => `
    <tr>
      <td>${r.timestamp}</td>
      <td>${r.source_ip}</td>
      <td>${r.attack_type}</td>
      <td>${r.service}</td>
      <td>${r.port}</td>
      <td>${r.severity}</td>
      <td>${r.blocked ? "Yes" : "No"}</td>
    </tr>
  `).join("");
}

refresh();
setInterval(refresh, 3000);
