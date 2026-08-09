import PlotlyPanel from './PlotlyPanel.jsx'

export default function Choropleth({ figure }) {
  return <PlotlyPanel title="Attack Volume by Country" figure={figure} />
}
