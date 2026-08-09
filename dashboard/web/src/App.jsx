import { useEffect, useState } from 'react'
import { io } from 'socket.io-client'

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

  return (
    <div style={{ fontFamily: 'monospace', padding: 20 }}>
      <p>Connected: {connected ? 'yes' : 'no'}</p>
      <pre>{data ? JSON.stringify(data.monitor, null, 2) : 'waiting for data...'}</pre>
    </div>
  )
}
