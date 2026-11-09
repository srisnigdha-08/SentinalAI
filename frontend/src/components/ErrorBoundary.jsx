import React from 'react'

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('[ErrorBoundary caught error]:', error, errorInfo)
    if (this.props.onError) {
      this.props.onError(error, errorInfo)
    }
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null })
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return typeof this.props.fallback === 'function'
          ? this.props.fallback({ error: this.state.error, reset: this.handleReset })
          : this.props.fallback
      }

      if (this.props.compact) {
        return (
          <div
            role="alert"
            style={{
              padding: '1.5rem',
              background: '#041120',
              border: '1px solid #ff2d55',
              borderRadius: 2,
              fontFamily: 'Share Tech Mono, monospace',
              color: '#c8e6f5',
              margin: '0.5rem 0',
            }}
          >
            <div style={{ color: '#ff2d55', fontWeight: 700, fontSize: 13, marginBottom: 6 }}>
              ⚠ COMPONENT RENDER ANOMALY
            </div>
            <div style={{ fontSize: 11, color: '#7ab3cc', marginBottom: 12 }}>
              {this.state.error?.message || 'An unexpected rendering error occurred in this module.'}
            </div>
            <button
              onClick={this.handleReset}
              style={{
                background: 'rgba(255, 45, 85, 0.15)',
                border: '1px solid #ff2d55',
                color: '#ff2d55',
                fontFamily: 'Share Tech Mono, monospace',
                fontSize: 11,
                padding: '4px 12px',
                borderRadius: 2,
                cursor: 'pointer',
              }}
            >
              Retry Module
            </button>
          </div>
        )
      }

      return (
        <div
          role="alert"
          style={{
            minHeight: '400px',
            height: '100%',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            background: '#020b18',
            color: '#c8e6f5',
            padding: '2rem',
            textAlign: 'center',
            fontFamily: 'Share Tech Mono, monospace',
          }}
        >
          <div
            style={{
              maxWidth: 580,
              width: '100%',
              background: '#081f35',
              border: '1px solid #ff2d55',
              borderRadius: 4,
              padding: '2.5rem',
              boxShadow: '0 0 30px rgba(255, 45, 85, 0.2)',
            }}
          >
            <div
              style={{
                fontFamily: 'Orbitron, sans-serif',
                fontSize: 18,
                fontWeight: 700,
                color: '#ff2d55',
                letterSpacing: 2,
                marginBottom: '0.75rem',
              }}
            >
              SENTINEL<span style={{ color: '#c8e6f5' }}>AI</span> // RUNTIME ANOMALY
            </div>
            <div style={{ fontSize: 12, color: '#ffaa00', letterSpacing: 1, marginBottom: '1.25rem' }}>
              // SUBSYSTEM EXCEPTION INTERCEPTED
            </div>
            <p style={{ fontFamily: 'Rajdhani, sans-serif', color: '#7ab3cc', fontSize: 14, lineHeight: 1.6, marginBottom: '1.5rem' }}>
              A critical rendering failure occurred while processing this interface. Security telemetry listeners remain active.
            </p>
            <div
              style={{
                background: '#041120',
                border: '1px solid #0d3352',
                borderRadius: 2,
                padding: '10px 14px',
                textAlign: 'left',
                fontSize: 11,
                color: '#ff2d55',
                marginBottom: '1.5rem',
                wordBreak: 'break-word',
                maxHeight: 120,
                overflowY: 'auto',
              }}
            >
              {this.state.error?.stack || this.state.error?.message || 'Unknown runtime exception'}
            </div>
            <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
              <button
                onClick={this.handleReset}
                style={{
                  background: '#00d4ff',
                  border: '1px solid #00d4ff',
                  color: '#000',
                  fontFamily: 'Rajdhani, sans-serif',
                  fontWeight: 700,
                  fontSize: 13,
                  letterSpacing: 1,
                  textTransform: 'uppercase',
                  padding: '8px 20px',
                  borderRadius: 2,
                  cursor: 'pointer',
                }}
              >
                Reinitialize Subsystem
              </button>
              <button
                onClick={() => window.location.reload()}
                style={{
                  background: 'transparent',
                  border: '1px solid #1a4a6e',
                  color: '#7ab3cc',
                  fontFamily: 'Rajdhani, sans-serif',
                  fontWeight: 600,
                  fontSize: 13,
                  letterSpacing: 1,
                  textTransform: 'uppercase',
                  padding: '8px 20px',
                  borderRadius: 2,
                  cursor: 'pointer',
                }}
              >
                Reload Application
              </button>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary
