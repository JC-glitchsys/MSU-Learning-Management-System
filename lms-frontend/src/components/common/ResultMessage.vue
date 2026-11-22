<template>
  <Teleport to="body">
    <Transition name="result-message">
      <div
        v-if="confirmation"
        class="fixed inset-0 z-[110] flex items-center justify-center bg-neutral-950/35 p-4"
        @click.self="finishConfirmation(false)"
        @keydown.esc="finishConfirmation(false)"
      >
        <section
          class="result-confirmation flex h-52 w-80 flex-col items-center overflow-hidden rounded-xl border border-neutral-200 bg-white px-6 text-center"
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="confirmation-title"
          aria-describedby="confirmation-message"
        >
          <div class="mt-5 flex h-12 w-12 items-center justify-center rounded-full bg-amber-100">
            <CircleAlert class="h-6 w-6 text-amber-600" :stroke-width="2" />
          </div>
          <h2 id="confirmation-title" class="mt-2 max-w-full truncate text-lg font-medium leading-7 text-neutral-900">
            {{ confirmation.title }}
          </h2>
          <p id="confirmation-message" class="line-clamp-2 text-xs font-normal leading-4 text-stone-500">
            {{ confirmation.message }}
          </p>
          <div class="mt-auto mb-4 flex w-full justify-center gap-2">
            <button class="rounded-lg border border-neutral-200 bg-white px-4 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-50" @click="finishConfirmation(false)">
              Cancel
            </button>
            <button class="rounded-lg bg-[#800000] px-4 py-2 text-sm font-medium text-white hover:bg-[#5C0000]" @click="finishConfirmation(true)">
              {{ confirmation.confirmLabel }}
            </button>
          </div>
        </section>
      </div>
    </Transition>
    <Transition name="result-message">
      <div
        v-if="result"
        class="result-confirmation fixed bottom-6 right-6 z-[100] flex h-52 w-80 flex-col items-center overflow-hidden rounded-xl border border-neutral-200 bg-white px-6 text-center"
        role="status"
        aria-live="polite"
      >
        <div
          class="mt-7 flex h-14 w-14 items-center justify-center rounded-full"
          :class="iconBackground"
        >
          <component :is="resultIcon" class="h-7 w-7" :class="iconColor" :stroke-width="2" />
        </div>
        <h2 class="mt-4 max-w-full truncate text-lg font-medium leading-7 text-neutral-900">
          {{ result.title }}
        </h2>
        <p class="mt-1 line-clamp-2 text-xs font-normal leading-4 text-stone-500">
          {{ result.message }}
        </p>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { Check, CircleAlert, Info } from 'lucide-vue-next'
import { currentResult } from '@/utils/resultMessage'

const result = currentResult
const confirmation = ref(null)
let dismissTimer

const resultIcon = computed(() => {
  if (result.value?.type === 'error') return CircleAlert
  if (result.value?.type === 'info') return Info
  return Check
})

const iconBackground = computed(() => ({
  'bg-red-100': result.value?.type === 'error',
  'bg-blue-100': result.value?.type === 'info',
  'bg-green-100': !['error', 'info'].includes(result.value?.type),
}))

const iconColor = computed(() => ({
  'text-red-600': result.value?.type === 'error',
  'text-blue-600': result.value?.type === 'info',
  'text-green-600': !['error', 'info'].includes(result.value?.type),
}))

function scheduleDismiss() {
  window.clearTimeout(dismissTimer)
  dismissTimer = window.setTimeout(() => { result.value = null }, 4200)
}

function requestConfirmation(event) {
  confirmation.value = event.detail
}

function finishConfirmation(accepted) {
  const pendingConfirmation = confirmation.value
  confirmation.value = null
  pendingConfirmation?.resolve(accepted)
}

function handleKeydown(event) {
  if (event.key === 'Escape' && confirmation.value) finishConfirmation(false)
}

onMounted(() => {
  window.addEventListener('lms:confirm', requestConfirmation)
  window.addEventListener('keydown', handleKeydown)
})
watch(result, (message) => {
  if (message) scheduleDismiss()
})
onUnmounted(() => {
  window.removeEventListener('lms:confirm', requestConfirmation)
  window.removeEventListener('keydown', handleKeydown)
  confirmation.value?.resolve(false)
  window.clearTimeout(dismissTimer)
})
</script>

<style scoped>
.result-message-enter-active,
.result-message-leave-active { transition: opacity 180ms ease, transform 180ms ease; }
.result-message-enter-from,
.result-message-leave-to { opacity: 0; transform: translateY(8px); }
.result-confirmation { box-shadow: 0 5px 15px 0 rgba(0, 0, 0, 0.35); }
@media (max-width: 639px) {
  .fixed.bottom-6.right-6 { right: 1rem; bottom: 1rem; width: calc(100vw - 2rem); }
}
</style>
