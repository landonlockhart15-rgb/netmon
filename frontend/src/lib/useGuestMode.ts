import { useCallback, useEffect, useState } from 'react'
import { getGuestMode, setGuestMode, type GuestModeState } from '@/lib/api'

type GuestModeListener = (state: GuestModeState | null) => void

interface UseGuestModeResult {
  state: GuestModeState | null
  loading: boolean
  toggle: (enabled: boolean) => Promise<void>
}

let cachedGuestModeState: GuestModeState | null = null

const listeners = new Set<GuestModeListener>()

const publishGuestModeState = (state: GuestModeState | null) => {
  cachedGuestModeState = state
  listeners.forEach((listener) => listener(state))
}

export const useGuestMode = (): UseGuestModeResult => {
  const [state, setState] = useState<GuestModeState | null>(cachedGuestModeState)
  const [loading, setLoading] = useState(cachedGuestModeState === null)

  useEffect(() => {
    let mounted = true

    const handleUpdate = (nextState: GuestModeState | null) => {
      if (mounted) {
        setState(nextState)
      }
    }

    const loadGuestMode = async (showLoading: boolean) => {
      if (showLoading) {
        setLoading(true)
      }

      try {
        const nextState = await getGuestMode()

        if (mounted) {
          publishGuestModeState(nextState)
        }
      } catch (error) {
        console.error('Failed to load guest mode state', error)
      } finally {
        if (mounted && showLoading) {
          setLoading(false)
        }
      }
    }

    listeners.add(handleUpdate)

    // Initial state/loading are already seeded from the cache via useState above;
    // the loader publishes any fresh value through handleUpdate.
    void loadGuestMode(cachedGuestModeState === null)

    const intervalId = window.setInterval(() => {
      void loadGuestMode(false)
    }, 10_000)

    return () => {
      mounted = false
      listeners.delete(handleUpdate)
      window.clearInterval(intervalId)
    }
  }, [])

  const toggle = useCallback(async (enabled: boolean) => {
    const previousState = cachedGuestModeState

    publishGuestModeState({
      guest_mode: enabled,
      blocked_features: previousState?.blocked_features ?? [],
      suppressed: previousState?.suppressed ?? [],
    })

    try {
      const nextState = await setGuestMode(enabled)
      publishGuestModeState(nextState)
    } catch (error) {
      publishGuestModeState(previousState)
      console.error('Failed to update guest mode state', error)
    }
  }, [])

  return { state, loading, toggle }
}
