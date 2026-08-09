export default function AlertTable({ events }) {
  if (!events || events.length === 0) {
    return (
      <div className="panel">
        <h3>Live Alert Stream</h3>
        <p className="empty-state">Waiting for detections…</p>
      </div>
    )
  }
  return (
    <div className="panel">
      <h3>Live Alert Stream</h3>
      <table className="alert-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Attack</th>
            <th>Src IP</th>
            <th>Conf</th>
            <th>Sev</th>
          </tr>
        </thead>
        <tbody>
          {events.slice(0, 20).map((e, i) => (
            <tr key={i}>
              <td>{e.time}</td>
              <td>{e.attack}</td>
              <td>{e.src_ip}</td>
              <td>{e.confidence}</td>
              <td>
                <span className={`chip ${e.severity}`}>{e.severity}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
