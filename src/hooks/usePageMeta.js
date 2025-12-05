import { useEffect } from 'react'

export function usePageMeta(title, description) {
  useEffect(() => {
    // Update document title
    if (title) {
      document.title = title
    }

    // Ensure and update <meta name="description">
    if (description) {
      let meta = document.querySelector('meta[name="description"]')

      if (!meta) {
        meta = document.createElement('meta')
        meta.name = 'description'
        document.head.appendChild(meta)
      }

      meta.content = description
    }
  }, [title, description])
}
