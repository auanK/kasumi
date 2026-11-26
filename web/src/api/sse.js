/**
 * Server-Sent Events client for /v1/events/stream with auth validation on error.
 */

export function connectEventStream({
  onStatus,
  onLog,
  onStateChange,
  checkSession,
  onSessionExpired,
} = {}) {
  let source = null
  let closed = false
  let retryMs = 1000
  let retryTimer = null
  let lastSeq = 0

  function setState(state) {
    if (onStateChange) onStateChange(state)
  }

  function closeInternal(state = 'disconnected') {
    closed = true
    if (retryTimer) {
      window.clearTimeout(retryTimer)
      retryTimer = null
    }
    if (source) {
      source.close()
      source = null
    }
    setState(state)
  }

  function open() {
    if (closed) return
    const url = lastSeq > 0 ? `/v1/events/stream?since=${lastSeq}` : '/v1/events/stream'
    source = new EventSource(url, { withCredentials: true })

    source.onopen = () => {
      retryMs = 1000
      setState('connected')
    }

    source.addEventListener('status', (evt) => {
      try {
        const data = JSON.parse(evt.data)
        if (onStatus) onStatus(data)
      } catch {
        // ignore malformed frame
      }
    })

    source.addEventListener('log', (evt) => {
      try {
        const data = JSON.parse(evt.data)
        if (data && typeof data.seq === 'number' && data.seq > lastSeq) {
          lastSeq = data.seq
        }
        if (onLog) onLog(data)
      } catch {
        // ignore malformed frame
      }
    })

    source.onerror = async () => {
      if (closed) return
      if (source) {
        source.close()
        source = null
      }
      if (checkSession) {
        try {
          const ok = await checkSession()
          if (closed) return
          if (!ok) {
            closeInternal('disconnected')
            if (onSessionExpired) onSessionExpired()
            return
          }
        } catch {
          if (closed) return
        }
      }
      setState('reconnecting')
      const delay = retryMs
      retryMs = Math.min(retryMs * 2, 15000)
      retryTimer = window.setTimeout(open, delay)
    }
  }

  setState('connecting')
  open()

  return {
    close() {
      closeInternal('disconnected')
    },
  }
}
