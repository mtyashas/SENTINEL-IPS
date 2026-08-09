import { useEffect, useState } from 'react'
import { io } from 'socket.io-client'
import KpiRow from './components/KpiRow.jsx'
import SystemHealth from './components/SystemHealth.jsx'
import ThroughputChart from './components/ThroughputChart.jsx'
import AlertTable from './components/AlertTable.jsx'
import AttackBarChart from './components/AttackBarChart.jsx'
import SeverityPie from './components/SeverityPie.jsx'
import WorldMap from './components/WorldMap.jsx'
import Choropleth from './components/Choropleth.jsx'
import MitreHeatmap from './components/MitreHeatmap.jsx'

export default function App() {
  const [connected, setConnected] = useState(false)
  const [data, setData] = useState(null)

  useEffect(() => {
    const socket = io()
    socket.on('connect', () => setConnected(true))
    socket.on('disconnect', () => setConnected(false))
    socket.on('dashboard_update', (payload) => setData(payload))
    return () => socket.disconnect()
  }, [])

  const monitor = data?.monitor ?? null
  const figures = data?.figures ?? {}

  return (
    <div className="app">
      <h1 className="header">SENTINEL IPS v2.0</h1>
      <p className="subheader">Real-Time Security Operations Centre</p>

      {!connected && <div className="banner-reconnecting">Reconnecting to dashboard server…</div>}

      <KpiRow monitor={monitor} uniqueIps={data?.unique_ips} />

      <div className="grid-2">
        <ThroughputChart series={monitor?.throughput_fps ?? []} />
        <AlertTable events={monitor?.events_list ?? []} />
      </div>

      <div className="grid-2">
        <AttackBarChart figure={figures.attack_bar} />
        <SeverityPie figure={figures.severity_pie} />
      </div>

      <WorldMap figure={figures.world_map} />
      <Choropleth figure={figures.choropleth} />
      <MitreHeatmap figure={figures.mitre_heatmap} />
      <SystemHealth health={data?.health} />
    </div>
  )
}
