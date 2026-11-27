<template>
  <div class="login-page min-h-svh bg-white">
    <main class="login-shell grid w-full lg:grid-cols-2">
      <section class="login-form-card flex w-full flex-col gap-4 p-6 md:p-10">
        <div class="flex flex-1 items-center justify-center">
          <div class="mx-auto w-full max-w-xs">
            <div class="mb-8 space-y-1 text-center">
              <h2 class="text-2xl font-semibold tracking-tight text-[#202124]">Welcome back</h2>
              <p class="text-sm leading-5 text-[#667085]">Sign in with your MSU account.</p>
            </div>

            <form class="space-y-5" @submit.prevent="handleLogin">
            <div class="space-y-1.5">
              <label class="block text-sm font-medium text-[#343A40]">Email</label>
              <div class="flex h-10 items-center gap-3 rounded-md border border-[#E2E5E9] px-3 transition focus-within:border-[#9B4B4B] focus-within:ring-2 focus-within:ring-[#800000]/10">
                <MailIcon class="h-4 w-4 shrink-0 text-[#98A2B3]" />
                <input
                  v-model="form.email"
                  type="email"
                  autocomplete="username"
                  placeholder="name@msu.edu.ph"
                  class="w-full border-0 bg-transparent p-0 text-sm text-[#202124] outline-none placeholder:text-[#98A2B3] focus:ring-0"
                />
              </div>
            </div>

            <div class="space-y-1.5">
              <div class="flex items-center justify-between">
                <label class="block text-sm font-medium text-[#343A40]">Password</label>
                <router-link to="/forgot-password" class="text-xs font-medium text-[#800000] transition hover:text-[#5C0000]">
                  Forgot password?
                </router-link>
              </div>
              <div class="flex h-10 items-center gap-3 rounded-md border border-[#E2E5E9] px-3 transition focus-within:border-[#9B4B4B] focus-within:ring-2 focus-within:ring-[#800000]/10">
                <LockIcon class="h-4 w-4 shrink-0 text-[#98A2B3]" />
                <input
                  v-model="form.password"
                  :type="showPassword ? 'text' : 'password'"
                  autocomplete="current-password"
                  placeholder="Enter your password"
                  class="w-full border-0 bg-transparent p-0 text-sm text-[#202124] outline-none placeholder:text-[#98A2B3] focus:ring-0"
                />
                <button
                  type="button"
                  @click="showPassword = !showPassword"
                  :aria-label="showPassword ? 'Hide password' : 'Show password'"
                  class="rounded-md p-1.5 text-[#667085] transition hover:bg-[#F3F4F6] hover:text-[#343A40]"
                >
                  <EyeIcon v-if="!showPassword" class="h-4 w-4" />
                  <EyeOffIcon v-else class="h-4 w-4" />
                </button>
              </div>
            </div>

            <p v-if="error" class="rounded-lg border border-[#F2D6D6] bg-[#FFF8F8] px-3.5 py-3 text-sm text-[#B3261E]" role="alert">
              {{ error }}
            </p>
            <button
              type="submit"
              :disabled="isLoading"
              class="inline-flex h-10 w-full items-center justify-center gap-2 rounded-md bg-[#800000] px-4 text-sm font-medium text-white transition-colors hover:bg-[#5C0000] disabled:cursor-not-allowed disabled:opacity-60"
            >
              <LogInIcon class="h-4 w-4" />
              {{ isLoading ? 'Signing in...' : 'Sign In' }}
            </button>
            </form>

            <p class="mt-8 border-t border-[#F0F1F3] pt-5 text-center text-xs text-[#98A2B3]">
              MSU Learn · {{ new Date().getFullYear() }}
            </p>
          </div>
        </div>
      </section>

      <aside class="login-brand relative hidden flex-col justify-between overflow-hidden bg-[#800000] p-12 text-white lg:flex lg:p-16">
        <img :src="msuLogo" alt="MSU Learn" class="h-auto w-56 max-w-full object-contain" />
        <div class="my-10 max-w-sm md:my-0">
          <h1 class="text-3xl font-medium leading-tight tracking-tight">Learning starts here.</h1>
          <p class="mt-3 max-w-xs text-sm leading-6 text-white/75">Your subjects, classwork, and grades in one place.</p>
        </div>
        <p class="text-xs leading-5 text-white/65">Mindanao State University</p>
      </aside>
    </main>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { signInWithEmailAndPassword } from 'firebase/auth'
import { doc, getDoc } from 'firebase/firestore'
import { auth, db } from '../../firebase/config.js'
import msuLogo from '@/assets/logologin.png'
import {
  EyeIcon,
  EyeOffIcon,
  LockIcon,
  LogInIcon,
  MailIcon,
} from 'lucide-vue-next'

const router = useRouter()

const error = ref('')
const isLoading = ref(false)
const showPassword = ref(false)

const form = ref({
  email: '',
  password: '',
})

function normalizeRole(role) {
  return String(role || '')
    .toLowerCase()
    .trim()
}

function getRoleFromProfile(profile) {
  const rawRole =
    profile.role ??
    profile.Role ??
    profile.userRole ??
    profile.accountType ??
    profile.type ??
    ''

  let role = normalizeRole(rawRole)

  if (role === 'teacher' || role === 'faculty' || role === 'professor') {
    role = 'instructor'
  }

  if (role === 'administrator' || role === 'superadmin') {
    role = 'admin'
  }

  if (role === 'learner' || role === 'students') {
    role = 'student'
  }

  return {
    rawRole,
    role,
  }
}

function getDashboardByRole(role) {
  const userRole = normalizeRole(role)

  if (userRole === 'admin') return '/admin/dashboard'
  if (userRole === 'instructor') return '/instructor/dashboard'
  if (userRole === 'student') return '/student/dashboard'

  return '/login'
}

function getFirebaseErrorMessage(code) {
  if (code === 'auth/invalid-email') return 'Please enter a valid email address.'
  if (code === 'auth/user-not-found') return 'No account found for this institutional email.'
  if (code === 'auth/wrong-password') return 'Incorrect password.'
  if (code === 'auth/invalid-credential') return 'Invalid email or password.'

  return 'Unable to sign in. Please try again.'
}

async function handleLogin() {
  error.value = ''

  if (!form.value.email.trim() || !form.value.password.trim()) {
    error.value = 'Please fill in all fields.'
    return
  }

  isLoading.value = true

  try {
    const credential = await signInWithEmailAndPassword(
      auth,
      form.value.email.trim(),
      form.value.password
    )

    const userDocRef = doc(db, 'users', credential.user.uid)
    const userDoc = await getDoc(userDocRef)

    if (!userDoc.exists()) {
      error.value = 'Account profile was not found in Firestore. Make sure users/{UID} exists.'
      return
    }

    const profile = userDoc.data()
    if (profile.archived === true) {
      error.value = 'This account has been archived. Contact an administrator if you need access restored.'
      return
    }
    const token = await credential.user.getIdToken()

    const { rawRole, role } = getRoleFromProfile(profile)

    if (!['admin', 'instructor', 'student'].includes(role)) {
      error.value = `Invalid user role: "${rawRole}". Use admin, instructor, or student.`
      return
    }

    localStorage.removeItem('user')

    localStorage.setItem(
      'user',
      JSON.stringify({
        id: credential.user.uid,
        uid: credential.user.uid,
        name: profile.name || credential.user.displayName || credential.user.email,
        email: credential.user.email,
        photoURL: profile.photoURL || credential.user.photoURL || '',
        role,
        token,
      })
    )

    await router.replace(getDashboardByRole(role))
  } catch (err) {
    console.log('Login error:', err.code, err.message)

    error.value = err.code
      ? getFirebaseErrorMessage(err.code)
      : 'An unexpected runtime error occurred.'
  } finally {
    isLoading.value = false
  }
}
</script>
