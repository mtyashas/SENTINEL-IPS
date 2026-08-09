export default function SystemHealth({ health }) {
  const tiles = [
    { lbl: 'CPU', val: health?.cpu_pct != null ? `${health.cpu_pct.toFixed(1)}%` : '—' },
    {
      lbl: 'RAM',
      val: health?.ram_used_gb != null
        ? `${health.ram_used_gb.toFixed(1)} / ${health.ram_total_gb.toFixed(1)} GB`
        : '—',
    },
    { lbl: 'RAM %', val: health?.ram_pct != null ? `${health.ram_pct.toFixed(1)}%` : '—' },
    { lbl: 'Disk Free', val: health?.disk_free_gb != null ? `${health.disk_free_gb.toFixed(1)} GB` : '—' },
  ]
  return (
    <div className="panel">
      <h3>System Health</h3>
      <div className="kpis">
        {tiles.map((t) => (
          <div className="kpi" key={t.lbl}>
            <div className="lbl">{t.lbl}</div>
            <div className="val">{t.val}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
