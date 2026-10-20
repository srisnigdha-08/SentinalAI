// REAL-TIME DETECTION FEED (DEFAULT)
import { useRealTimeFeed } from '../hooks/useRealTimeFeed.js'
import SeverityBadge from './SeverityBadge.jsx'

export default function LiveFeed() {
  // REAL DATA SOURCE:
  // Listens to real detection pipeline events emitted by backend via Socket.IO
  const { feed, connected } = useRealTimeFeed(30)

  return (
    <div style={{
      maxHeight: 260, overflowY: 'auto',
      fontFamily: 'Share Tech Mono,monospace', fontSize: 12,
    }}>
      {feed.length === 0 ? (
        <div style={{
          padding: '2.5rem 1rem', textAlign: 'center',
          color: '#3a6a88', display: 'flex', flexDirection: 'column',
          alignItems: 'center', gap: 8
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{
              width: 7, height: 7, borderRadius: '50%',
              background: connected ? '#00ff88' : '#ffaa00',
              animation: 'pulseDot 2s ease-in-out infinite'
            }} />
            <span style={{ color: '#7ab3cc', fontSize: 13, letterSpacing: 1 }}>
              No attacks detected yet
            </span>
          </div>
          <span style={{ fontSize: 11, color: '#274b68' }}>
            {connected ? 'Waiting for live events...' : 'Connecting to real-time event pipeline...'}
          </span>
        </div>
      ) : (
        feed.map(item => (
          <div key={item.id} style={{
            padding: '6px 0', borderBottom: '1px solid rgba(13,51,82,.4)',
            display: 'flex', gap: 10, alignItems: 'flex-start',
            animation: 'feedSlide .3s ease',
          }}>
            <span style={{ color: '#3a6a88', whiteSpace: 'nowrap', fontSize: 11 }}>{item.ts}</span>
            <span style={{ color: '#00d4ff' }}>{item.ip}</span>
            <span style={{ color: '#7ab3cc', flex: 1, fontSize: 11 }}>{item.msg}</span>
            <SeverityBadge sev={item.sev} />
          </div>
        ))
      )}
    </div>
  )
}
