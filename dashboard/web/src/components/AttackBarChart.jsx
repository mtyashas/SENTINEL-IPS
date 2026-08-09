import PlotlyPanel from './PlotlyPanel.jsx'

export default function AttackBarChart({ figure }) {
  return <PlotlyPanel title="Attack Type Distribution" figure={figure} />
}
