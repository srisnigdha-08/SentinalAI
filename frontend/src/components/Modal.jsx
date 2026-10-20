import React, { useEffect, useRef } from 'react'

export default function Modal({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  maxWidth = '560px',
  borderColor = '#00d4ff',
  glowColor = 'rgba(0, 212, 255, 0.2)',
  titleColor,
  dismissible = true,
}) {
  const modalRef = useRef(null)
  const previousActiveElement = useRef(null)
  // Read via ref so a new onClose identity on parent re-render doesn't re-run the focus effect
  const requestCloseRef = useRef(null)
  requestCloseRef.current = () => { if (dismissible) onClose?.() }

  // Body scroll lock
  useEffect(() => {
    if (!isOpen) return

    previousActiveElement.current = document.activeElement
    const originalOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'

    return () => {
      document.body.style.overflow = originalOverflow
      if (previousActiveElement.current && typeof previousActiveElement.current.focus === 'function') {
        previousActiveElement.current.focus()
      }
    }
  }, [isOpen])

  // Escape key listener & Focus Trap
  useEffect(() => {
    if (!isOpen) return

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        requestCloseRef.current()
        return
      }

      if (e.key === 'Tab' && modalRef.current) {
        const focusableElements = modalRef.current.querySelectorAll(
          'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )
        if (focusableElements.length === 0) return

        const firstElement = focusableElements[0]
        const lastElement = focusableElements[focusableElements.length - 1]

        if (e.shiftKey) {
          if (document.activeElement === firstElement) {
            e.preventDefault()
            lastElement.focus()
          }
        } else {
          if (document.activeElement === lastElement) {
            e.preventDefault()
            firstElement.focus()
          }
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown)

    // Move initial focus into modal
    const timer = setTimeout(() => {
      if (modalRef.current) {
        const focusable = modalRef.current.querySelector(
          'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])'
        )
        if (focusable) focusable.focus()
        else modalRef.current.focus()
      }
    }, 50)

    return () => {
      window.removeEventListener('keydown', handleKeyDown)
      clearTimeout(timer)
    }
  }, [isOpen])

  if (!isOpen) return null

  const titleId = 'modal-title-' + (title ? title.replace(/\s+/g, '-').toLowerCase() : 'dialog')

  return (
    <div
      onClick={(e) => {
        if (e.target === e.currentTarget) requestCloseRef.current()
      }}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(2, 8, 16, 0.85)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '1rem',
      }}
    >
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        style={{
          background: '#041120',
          border: `1px solid ${borderColor}`,
          boxShadow: `0 0 30px ${glowColor}`,
          borderRadius: '4px',
          maxWidth,
          width: '100%',
          padding: '1.5rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1.25rem',
          outline: 'none',
          maxHeight: '90vh',
          overflowY: 'auto',
        }}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            borderBottom: `1px solid ${borderColor}44`,
            paddingBottom: '0.75rem',
          }}
        >
          <div>
            <h2
              id={titleId}
              style={{
                fontFamily: 'Orbitron, sans-serif',
                fontSize: 16,
                fontWeight: 700,
                color: titleColor || borderColor,
                margin: 0,
              }}
            >
              {title}
            </h2>
            {subtitle && (
              <div
                style={{
                  fontFamily: 'Share Tech Mono, monospace',
                  fontSize: 10,
                  color: '#7ab3cc',
                  letterSpacing: 1,
                  marginTop: 2,
                }}
              >
                {subtitle}
              </div>
            )}
          </div>
          <button
            onClick={() => requestCloseRef.current()}
            disabled={!dismissible}
            aria-label="Close dialog"
            style={{
              background: 'none',
              border: 'none',
              color: '#7ab3cc',
              fontSize: 18,
              cursor: 'pointer',
              padding: '4px 8px',
              borderRadius: 2,
              lineHeight: 1,
            }}
            onMouseEnter={(e) => (e.target.style.color = '#ff2d55')}
            onMouseLeave={(e) => (e.target.style.color = '#7ab3cc')}
          >
            ✕
          </button>
        </div>

        {/* Content */}
        {children}
      </div>
    </div>
  )
}
