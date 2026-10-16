import { REPORT_TIME_ZONE } from '../utils/reportingTime.js'
import { useState } from 'react'
import { useRealTimeAlerts } from '../hooks/useRealTimeAlerts.js'

const SEV_COLOR = { CRITICAL:'#ff2d55', HIGH:'#ff6400', MEDIUM:'#ffaa00', INFO:'#00d4ff' }

export default function AlertBell() {
  const [open, setOpen] = useState(false)
  const { alerts, unreadCount, markRead, markAllRead } = useRealTimeAlerts()

  return (
    <div style={{ position:'relative' }}>
      {/* Bell button */}
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          background:'transparent', border:'1px solid #1a4a6e',
          borderRadius:2, padding:'6px 10px', cursor:'pointer',
          color: unreadCount > 0 ? '#ff2d55' : '#7ab3cc',
          fontFamily:'Share Tech Mono,monospace', fontSize:12,
          position:'relative', transition:'all .2s',
        }}
      >
        🔔 {unreadCount > 0 && (
          <span style={{
            position:'absolute', top:-6, right:-6,
            background:'#ff2d55', color:'#fff',
            borderRadius:'50%', width:16, height:16,
            display:'flex', alignItems:'center', justifyContent:'center',
            fontFamily:'Share Tech Mono,monospace', fontSize:9, fontWeight:700,
          }}>{unreadCount > 9 ? '9+' : unreadCount}</span>
        )}
      </button>

      {/* Dropdown panel */}
      {open && (
        <>
          {/* Backdrop */}
          <div
            onClick={() => setOpen(false)}
            style={{ position:'fixed', inset:0, zIndex:999 }}
          />
          <div style={{
            position:'absolute', top:'calc(100% + 8px)', right:0,
            width:340, background:'#081f35',
            border:'1px solid #0d3352', borderRadius:2,
            zIndex:1000, maxHeight:400, overflowY:'auto',
            boxShadow:'0 8px 32px rgba(0,0,0,.6)',
          }}>
            {/* Header */}
            <div style={{
              padding:'10px 14px', borderBottom:'1px solid #0d3352',
              display:'flex', alignItems:'center', justifyContent:'space-between',
            }}>
              <span style={{ fontFamily:'Orbitron,sans-serif', fontSize:11, fontWeight:700, color:'#7ab3cc', letterSpacing:2 }}>
                ALERTS
              </span>
              {unreadCount > 0 && (
                <button onClick={markAllRead} style={{
                  background:'transparent', border:'none', color:'#00d4ff',
                  fontFamily:'Share Tech Mono,monospace', fontSize:10, cursor:'pointer',
                }}>Mark all read</button>
              )}
            </div>

            {/* Alert list */}
            {alerts.length === 0 ? (
              <div style={{ padding:'1.5rem', textAlign:'center', color:'#3a6a88',
                fontFamily:'Share Tech Mono,monospace', fontSize:11 }}>
                No unread alerts
              </div>
            ) : alerts.map((a, i) => (
              <div key={a._id || i} style={{
                padding:'10px 14px', borderBottom:'1px solid rgba(13,51,82,.5)',
                display:'flex', gap:10, alignItems:'flex-start',
                cursor:'pointer', transition:'background .15s',
              }}
                onMouseEnter={e => e.currentTarget.style.background='rgba(0,212,255,.04)'}
                onMouseLeave={e => e.currentTarget.style.background='transparent'}
                onClick={() => markRead(a._id)}
              >
                <div style={{
                  width:6, height:6, borderRadius:'50%', flexShrink:0, marginTop:5,
                  background: SEV_COLOR[a.severity] || '#7ab3cc',
                }} />
                <div style={{ flex:1 }}>
                  <div style={{ fontSize:12, fontWeight:600, color:'#c8e6f5', marginBottom:2 }}>{a.title}</div>
                  <div style={{ fontSize:11, color:'#7ab3cc', lineHeight:1.5 }}>{a.message}</div>
                  <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#3a6a88', marginTop:4 }}>
                    {a.createdAt ? new Date(a.createdAt).toLocaleTimeString('en-IN',{ timeZone: REPORT_TIME_ZONE,hour12:false}) : 'Just now'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
