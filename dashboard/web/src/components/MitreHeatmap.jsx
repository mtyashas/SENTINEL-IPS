import PlotlyPanel from './PlotlyPanel.jsx'

export default function MitreHeatmap({ figure }) {
  return <PlotlyPanel title="MITRE ATT&CK Coverage Matrix" figure={figure} />
}
