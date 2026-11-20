// This pulls the metrics API every 5s. Served as a static file so the CSP can forbid inline scripts.
(function () {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  const bar = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  const chartSeries = document.getElementById("history-series");
  const historyEmpty = document.getElementById("history-empty");
  let lastHistoryRefresh = 0;

  function drawHistory(samples) {
    if (!chartSeries) return;
    chartSeries.textContent = "";
    if (samples.length < 2) {
      if (historyEmpty) {
        historyEmpty.hidden = false;
        historyEmpty.textContent = "Collecting samples. The chart will appear as history builds.";
      }
      return;
    }

    if (historyEmpty) historyEmpty.hidden = true;
    const now = Date.now() / 1000;
    const start = now - 24 * 60 * 60;
    const width = 642;
    const height = 152;
    const series = [
      { key: "cpu_percent", color: "#16839c" },
      { key: "mem_percent", color: "#f4a340" },
      { key: "disk_percent", color: "#7aa94d" }
    ];

    series.forEach(({ key, color }) => {
      const points = samples.map(sample => {
        const x = 58 + Math.max(0, Math.min(1, (sample.time - start) / (now - start))) * width;
        const value = Math.max(0, Math.min(100, Number(sample[key])));
        const y = 20 + (100 - value) / 100 * height;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      });
      const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
      line.setAttribute("points", points.join(" "));
      line.setAttribute("fill", "none");
      line.setAttribute("stroke", color);
      line.setAttribute("stroke-width", "3");
      line.setAttribute("stroke-linecap", "round");
      line.setAttribute("stroke-linejoin", "round");
      chartSeries.appendChild(line);
    });
  }

  async function refreshHistory() {
    const response = await fetch("/api/metrics/history", { credentials: "same-origin" });
    if (!response.ok) throw new Error(`History request failed (${response.status})`);
    const data = await response.json();
    drawHistory(data.samples);
    set("history-updated", "Updated " + new Date().toLocaleTimeString());
    lastHistoryRefresh = Date.now();
  }

  async function refresh() {
    try {
      const r = await fetch("/api/metrics", { credentials: "same-origin" });
      if (!r.ok) throw new Error(`Metrics request failed (${r.status})`);
      const m = await r.json();
      set("cpu", m.cpu_percent); bar("cpu-bar", m.cpu_percent);
      set("load", m.load.join(" / "));
      set("mem", m.mem_percent); bar("mem-bar", m.mem_percent); set("mem-used", m.mem_used_mb);
      set("disk", m.disk_percent); bar("disk-bar", m.disk_percent); set("disk-used", m.disk_used_gb);
      set("uptime", m.uptime_min);
      set("updated", "live \u00b7 " + new Date().toLocaleTimeString());
      if (Date.now() - lastHistoryRefresh >= 60000) await refreshHistory();
    } catch (error) {
      console.error("Unable to refresh dashboard metrics or history.", error);
      if (historyEmpty && !chartSeries.childElementCount) {
        historyEmpty.hidden = false;
        historyEmpty.textContent = "Unable to load resource history. Please retry.";
      }
    }
  }
  refresh();
  setInterval(refresh, 5000);
})();
