<template>
  <div class="login-page min-h-svh bg-white">
    <main class="login-shell grid w-full lg:grid-cols-2">
      <section class="login-form-card flex w-full flex-col gap-4 p-6 md:p-10">
        <div class="flex flex-1 items-center justify-center">
          <div class="mx-auto w-full max-w-xs">
            <div class="mb-8 space-y-1 text-center">
              <h1 class="text-2xl font-semibold tracking-tight text-[#202124]">Forgot password?</h1>
              <p class="text-sm leading-5 text-[#667085]">
                Enter your email and we’ll send you a link to reset your password.
              </p>
            </div>

            <form class="space-y-5" @submit.prevent="handleReset">
              <div class="space-y-1.5">
                <label for="reset-email" class="block text-sm font-medium text-[#343A40]">Email</label>
                <div class="flex h-10 items-center gap-3 rounded-md border border-[#E2E5E9] px-3 transition focus-within:border-[#9B4B4B] focus-within:ring-2 focus-within:ring-[#800000]/10">
                  <MailIcon class="h-4 w-4 shrink-0 text-[#98A2B3]" />
                  <input
                    id="reset-email"
                    v-model="email"
                    type="email"
                    autocomplete="email"
                    required
                    placeholder="name@msu.edu.ph"
                    class="w-full border-0 bg-transparent p-0 text-sm text-[#202124] outline-none placeholder:text-[#98A2B3] focus:ring-0"
                  />
                </div>
              </div>

              <p v-if="error" class="rounded-lg border border-[#F2D6D6] bg-[#FFF8F8] px-3.5 py-3 text-sm text-[#B3261E]" role="alert">
                {{ error }}
              </p>
              <p v-if="message" class="rounded-lg bg-[#F4F7F4] px-3.5 py-3 text-sm text-[#336B45]" role="status" aria-live="polite">
                {{ message }}
              </p>

              <button
                type="submit"
                :disabled="isLoading"
                class="inline-flex h-10 w-full items-center justify-center gap-2 rounded-md bg-[#800000] px-4 text-sm font-medium text-white transition-colors hover:bg-[#5C0000] disabled:cursor-not-allowed disabled:opacity-60"
              >
                {{ isLoading ? 'Sending link...' : 'Send reset link' }}
              </button>
            </form>

            <p class="mt-6 text-center text-sm text-[#667085]">
              Remember your password?
              <router-link to="/login" class="font-medium text-[#800000] hover:underline">Back to sign in</router-link>
            </p>
          </div>
        </div>
      </section>

      <aside class="login-brand relative hidden flex-col justify-between overflow-hidden bg-[#800000] p-12 text-white lg:flex lg:p-16">
        <img :src="msuLogo" alt="MSU Learn" class="h-auto w-56 max-w-full object-contain" />
        <div class="my-10 max-w-sm md:my-0">
          <h2 class="forgot-password-brand-heading text-3xl font-medium leading-tight tracking-tight">Learning starts here.</h2>
          <p class="mt-3 max-w-xs text-sm leading-6 text-white/75">Your subjects, classwork, and grades in one place.</p>
        </div>
        <p class="text-xs leading-5 text-white/65">Mindanao State University</p>
      </aside>
    </main>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { sendPasswordResetEmail } from 'firebase/auth'
import { auth } from '../../firebase/config.js'
import msuLogo from '@/assets/logologin.png'
import { MailIcon } from 'lucide-vue-next'

const email = ref('')
const error = ref('')
const message = ref('')
const isLoading = ref(false)

async function handleReset() {
  error.value = ''
  message.value = ''
  isLoading.value = true

  try {
    await sendPasswordResetEmail(auth, email.value.trim())
    message.value = 'If an account exists for this email, a password reset link is on the way.'
  } catch (err) {
    error.value = err.code === 'auth/invalid-email'
      ? 'Please enter a valid email address.'
      : 'Unable to send a reset link right now. Please try again.'
  } finally {
    isLoading.value = false
  }
}
</script>

<style scoped>
.forgot-password-brand-heading {
  color: #fff !important;
}
</style>
