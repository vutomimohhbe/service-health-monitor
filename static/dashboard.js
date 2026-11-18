// Polls the metrics API every 5s. Served as a static file so the CSP can forbid inline scripts.
(function () {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  const bar = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  async function refresh() {
    try {
      const r = await fetch("/api/metrics", { credentials: "same-origin" });
      if (!r.ok) return;
      const m = await r.json();
      set("cpu", m.cpu_percent); bar("cpu-bar", m.cpu_percent);
      set("load", m.load.join(" / "));
      set("mem", m.mem_percent); bar("mem-bar", m.mem_percent); set("mem-used", m.mem_used_mb);
      set("disk", m.disk_percent); bar("disk-bar", m.disk_percent); set("disk-used", m.disk_used_gb);
      set("uptime", m.uptime_min);
      set("updated", "live \u00b7 " + new Date().toLocaleTimeString());
    } catch (e) { /* ignore transient errors */ }
  }
  setInterval(refresh, 5000);
})();
