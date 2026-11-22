import { ref } from 'vue'

export const currentResult = ref(null)

export function showResult(title, message, type = 'success') {
  if (typeof window === 'undefined') return
  currentResult.value = { title, message, type }
}

export function confirmAction(title, message, confirmLabel = 'Confirm') {
  if (typeof window === 'undefined') return Promise.resolve(false)

  return new Promise((resolve) => {
    window.dispatchEvent(new CustomEvent('lms:confirm', {
      detail: { title, message, confirmLabel, resolve },
    }))
  })
}
