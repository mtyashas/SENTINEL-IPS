import createPlotlyComponent from 'react-plotly.js/factory'
import Plotly from 'plotly.js-dist-min'

const Plot = createPlotlyComponent(Plotly)

export default function PlotlyPanel({ title, figure }) {
  if (!figure) {
    return (
      <div className="panel">
        <h3>{title}</h3>
        <p className="empty-state">No data yet.</p>
      </div>
    )
  }
  return (
    <div className="panel">
      <h3>{title}</h3>
      <Plot
        data={figure.data}
        layout={{ ...figure.layout, autosize: true, margin: { l: 10, r: 10, t: 10, b: 10 } }}
        style={{ width: '100%', height: '320px' }}
        useResizeHandler
        config={{ displayModeBar: false, responsive: true }}
      />
    </div>
  )
}
