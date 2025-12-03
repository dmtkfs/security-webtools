import { useState, useEffect } from 'react'

export function useLocalStorage(key, defaultValue) {
  const [value, setValue] = useState(() => {
    if (typeof window === 'undefined') return defaultValue
    try {
      const stored = window.localStorage.getItem(key)
      return stored !== null ? JSON.parse(stored) : defaultValue
    } catch {
      return defaultValue
    }
  })

  useEffect(() => {
    if (typeof window === 'undefined') return
    try {
      window.localStorage.setItem(key, JSON.stringify(value))
    } catch {
      // ignore quota / privacy errors
    }
  }, [key, value])

  return [value, setValue]
}
