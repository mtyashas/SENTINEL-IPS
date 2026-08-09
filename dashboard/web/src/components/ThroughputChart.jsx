export default function ThroughputChart({ series }) {
  const data = series && series.length > 0 ? series : [0]
  const max = Math.max(...data, 1)
  const min = Math.min(...data, 0)
  const range = max - min || 1
  const w = 400
  const h = 120
  const step = data.length > 1 ? w / (data.length - 1) : 0

  const points = data
    .map((v, i) => {
      const x = i * step
      const y = h - ((v - min) / range) * h
      return `${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')

  const lastX = (data.length - 1) * step
  const lastY = h - ((data[data.length - 1] - min) / range) * h

  return (
    <div className="panel">
      <h3>Live Throughput (flows/sec)</h3>
      <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
        <polyline
          points={points}
          fill="none"
          stroke="#5AD1E6"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <circle cx={lastX} cy={lastY} r="4" fill="#5AD1E6" />
      </svg>
    </div>
  )
}
