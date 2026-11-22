<template>
  <div class="login-page flex min-h-screen items-center justify-center bg-[#F8F9FA] px-4 py-8 sm:px-8">
    <main class="login-shell grid w-full max-w-5xl overflow-hidden rounded-2xl border border-[#DADCE0] bg-white md:grid-cols-[0.9fr_1.1fr]">
      <aside class="login-brand flex flex-col justify-between bg-[#800000] p-8 text-white sm:p-10">
        <div class="flex items-center gap-3">
          <img :src="msuLogo" alt="Mindanao State University" class="h-11 w-11 rounded-md bg-white p-1 object-contain" />
          <div>
            <p class="text-sm font-semibold leading-5">Mindanao State University</p>
            <p class="text-xs leading-4 text-white/70">Learning Management System</p>
          </div>
        </div>
        <div class="my-10 max-w-sm md:my-0">
          <p class="text-xs font-medium uppercase tracking-[0.16em] text-white/65">MSU LMS</p>
          <h1 class="mt-3 text-3xl font-semibold leading-tight tracking-tight text-white">Your learning, in one place.</h1>
          <p class="mt-4 max-w-xs text-sm leading-6 text-white/80">Access your subjects, course materials, activities, and academic progress through your university account.</p>
        </div>
        <p class="text-xs leading-5 text-white/65">A shared academic workspace for students and faculty.</p>
      </aside>

      <section class="flex items-center justify-center px-6 py-10 sm:px-12 sm:py-14">
      <div class="w-full max-w-md">
      <div class="mb-8">
        <p class="text-xs font-medium uppercase tracking-wide text-[#5F6368]">Welcome back</p>
        <h2 class="mt-2 text-2xl font-semibold tracking-tight text-[#202124]">Sign in to your account</h2>
        <p class="mt-2 text-sm leading-5 text-[#5F6368]">Use your institutional account to access your LMS workspace.</p>
      </div>

      <form class="space-y-5" @submit.prevent="handleLogin">
        <div class="space-y-1.5">
          <label class="block text-sm font-medium text-[#202124]">Email address</label>
          <div class="flex items-center gap-3 rounded border border-[#DADCE0] px-3 py-2.5 focus-within:border-[#800000]">
            <MailIcon class="h-4 w-4 shrink-0 text-[#5F6368]" />
            <input
              v-model="form.email"
              type="email"
              autocomplete="username"
              placeholder="you@msu.edu.ph"
              class="w-full border-0 bg-transparent p-0 text-sm text-[#202124] outline-none focus:ring-0"
            />
          </div>
        </div>

        <div class="space-y-1.5">
          <label class="block text-sm font-medium text-[#202124]">Password</label>
          <div class="flex items-center gap-3 rounded border border-[#DADCE0] px-3 py-2.5 focus-within:border-[#800000]">
            <LockIcon class="h-4 w-4 shrink-0 text-[#5F6368]" />
            <input
              v-model="form.password"
              :type="showPassword ? 'text' : 'password'"
              autocomplete="current-password"
              placeholder="Enter your password"
              class="w-full border-0 bg-transparent p-0 text-sm text-[#202124] outline-none focus:ring-0"
            />
            <button
              type="button"
              @click="showPassword = !showPassword"
              :aria-label="showPassword ? 'Hide password' : 'Show password'"
              class="rounded p-1 text-[#5F6368] hover:bg-[#F1F3F4]"
            >
              <EyeIcon v-if="!showPassword" class="h-4 w-4" />
              <EyeOffIcon v-else class="h-4 w-4" />
            </button>
          </div>
        </div>

        <p v-if="error" class="rounded border border-[#DADCE0] bg-[#F8F9FA] px-3 py-2 text-sm text-[#D93025]">
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

      <p class="mt-7 border-t border-[#DADCE0] pt-5 text-center text-xs text-[#5F6368]">
        MSU LMS &copy; {{ new Date().getFullYear() }} · Mindanao State University
      </p>
      </div>
      </section>
    </main>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { signInWithEmailAndPassword } from 'firebase/auth'
import { doc, getDoc } from 'firebase/firestore'
import { auth, db } from '../../firebase/config.js'
import msuLogo from '@/assets/logo.png'
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
