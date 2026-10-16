import { useSocket } from '../hooks/useSocket.js'

export default function ConnectionStatus() {
  const { connected, reconnecting } = useSocket()

  if (connected) return null  // Hide when all is well

  return (
    <div style={{
      position:'fixed', bottom:'1rem', left:'50%', transform:'translateX(-50%)',
      background: reconnecting ? 'rgba(255,170,0,.15)' : 'rgba(255,45,85,.15)',
      border: `1px solid ${reconnecting ? '#ffaa00' : '#ff2d55'}`,
      borderRadius:2, padding:'8px 20px',
      fontFamily:'Share Tech Mono,monospace', fontSize:11,
      color: reconnecting ? '#ffaa00' : '#ff2d55',
      zIndex:8000, display:'flex', alignItems:'center', gap:8,
    }}>
      <div style={{
        width:6, height:6, borderRadius:'50%',
        background: reconnecting ? '#ffaa00' : '#ff2d55',
        animation:'pulseDot 1s ease-in-out infinite',
      }} />
      {/* SIMULATION NOTE: Previously read 'REAL-TIME FEED DISCONNECTED — SHOWING SIMULATED DATA'.
          In REAL DATA MODE, missing connection does NOT trigger fake data. */}
      {reconnecting ? 'RECONNECTING TO SENTINEL...' : 'REAL-TIME FEED DISCONNECTED — LIVE STREAM OFFLINE'}
    </div>
  )
}
