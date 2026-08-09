export default function KpiRow({ monitor, uniqueIps }) {
  const fps = monitor?.current_fps ?? 0
  const fpsDisplay = fps >= 1000
    ? fps.toLocaleString(undefined, { maximumFractionDigits: 0 })
    : Math.round(fps).toString()
  const uptimeS = monitor?.uptime_s ?? 0
  const uptime = new Date(uptimeS * 1000).toISOString().substring(11, 19)

  const tiles = [
    { lbl: 'Flows/sec', val: fpsDisplay },
    { lbl: 'Total Attacks', val: (monitor?.total_attacks ?? 0).toLocaleString() },
    { lbl: 'Total Flows', val: (monitor?.total_flows ?? 0).toLocaleString() },
    { lbl: 'Unique IPs', val: (uniqueIps ?? 0).toLocaleString() },
    { lbl: 'Uptime', val: uptime },
  ]

  return (
    <div className="kpis">
      {tiles.map((t) => (
        <div className="kpi" key={t.lbl}>
          <div className="lbl">{t.lbl}</div>
          <div className="val">{t.val}</div>
        </div>
      ))}
    </div>
  )
}
