<template>
  <div
    class="login-page relative flex min-h-screen items-center justify-center overflow-hidden bg-gradient-to-br from-[#FFFDF8] via-white to-[#FFF8E1] px-4 py-10"
  >
    <!-- Soft Background Glows -->
    <div class="pointer-events-none absolute inset-0 overflow-hidden">
      <div class="absolute -left-24 top-16 h-72 w-72 rounded-full bg-[#800000]/[0.05] blur-3xl"></div>
      <div class="absolute -right-20 bottom-10 h-80 w-80 rounded-full bg-[#D4AF37]/[0.16] blur-3xl"></div>
      <div class="absolute left-1/2 top-1/3 h-72 w-72 -translate-x-1/2 rounded-full bg-[#800000]/[0.04] blur-3xl"></div>
    </div>

    <!-- Main Floating Shell -->
    <main
      class="relative z-10 grid w-full max-w-6xl overflow-hidden rounded-[34px] border border-[#E7DCC3] bg-white/90 shadow-[0_24px_70px_rgba(90,0,0,0.12)] backdrop-blur-xl lg:grid-cols-[1fr_1fr]"
    >
      <!-- Left Branding Panel -->
      <section
        class="relative hidden min-h-[620px] overflow-hidden bg-gradient-to-br from-[#800000] via-[#7A0707] to-[#B98718] p-10 text-white lg:flex lg:flex-col lg:justify-between"
      >
        <div class="absolute -right-20 -top-20 h-64 w-64 rounded-full bg-white/10"></div>
        <div class="absolute bottom-12 right-10 h-28 w-28 rounded-full bg-[#D4AF37]/20 blur-xl"></div>
        <div class="absolute -bottom-20 -left-16 h-60 w-60 rounded-full bg-black/10"></div>

        <div class="relative">
          <div
            class="inline-flex items-center gap-3 rounded-full border border-white/20 bg-white/10 px-4 py-2 shadow-[inset_0_1px_8px_rgba(255,255,255,0.12)] backdrop-blur-md"
          >
            <img
              :src="msuSeal"
              alt="MSU Seal"
              class="h-10 w-10 object-contain drop-shadow-md"
            />

            <div>
              <p class="text-[11px] font-semibold uppercase tracking-[0.2em] text-white">
                Mindanao State University
              </p>
              <p class="text-[10px] font-light uppercase tracking-[0.18em] text-white/70">
                Learning Management System
              </p>
            </div>
          </div>

          <div class="mt-16 max-w-md">
            <p class="text-xs font-semibold uppercase tracking-[0.28em] text-[#F5D56E]">
              MSU LMS
            </p>

            <h1 class="mt-4 text-3xl font-semibold leading-[1.15] tracking-[-0.03em] text-white xl:text-4xl">
              Learn, teach, and manage classes in one academic space.
            </h1>

            <p class="mt-5 max-w-sm text-sm font-light leading-7 text-white/78">
              A clean digital platform for students, instructors, and administrators
              to manage subjects, modules, activities, submissions, and grades.
            </p>
          </div>
        </div>

        <div class="relative grid grid-cols-2 gap-3">
          <div class="rounded-[22px] border border-white/15 bg-white/10 p-4 backdrop-blur">
            <p class="text-[11px] font-semibold uppercase tracking-wider text-[#F5D56E]">
              Students
            </p>
            <p class="mt-2 text-xs font-light leading-5 text-white/80">
              Access subjects, classwork, and grades.
            </p>
          </div>

          <div class="rounded-[22px] border border-white/15 bg-white/10 p-4 backdrop-blur">
            <p class="text-[11px] font-semibold uppercase tracking-wider text-[#F5D56E]">
              Faculty
            </p>
            <p class="mt-2 text-xs font-light leading-5 text-white/80">
              Upload modules and evaluate submissions.
            </p>
          </div>
        </div>
      </section>

      <!-- Right Login Panel -->
      <section class="flex min-h-[620px] items-center justify-center p-6 sm:p-10">
        <div class="w-full max-w-md">
          <!-- Mobile Brand: logo only, no circle -->
          <div class="mb-8 text-center lg:hidden">
            <img
              :src="msuSeal"
              alt="MSU Seal"
              class="mx-auto mb-4 h-20 w-20 object-contain drop-shadow-sm"
            />

            <h1 class="text-2xl font-semibold tracking-tight text-[#800000]">
              MSU LMS
            </h1>
            <p class="mt-1 text-sm font-light text-[#6B7280]">
              Mindanao State University
            </p>
          </div>

          <!-- Login Card -->
          <div
            class="rounded-[30px] border border-[#E7DCC3] bg-white p-7 shadow-[0_14px_40px_rgba(31,41,55,0.08)] sm:p-8"
          >
            <div class="mb-7">
              <div class="hidden items-center gap-4 lg:flex">
                <!-- Desktop logo: logo only, no circle -->
                <img
                  :src="msuSeal"
                  alt="MSU Seal"
                  class="h-16 w-16 shrink-0 object-contain drop-shadow-sm"
                />

                <div>
                  <p class="text-[11px] font-semibold uppercase tracking-[0.22em] text-[#D4AF37]">
                    Welcome Back
                  </p>
                  <h2 class="text-xl font-semibold tracking-tight text-[#800000]">
                    Sign in to your account
                  </h2>
                </div>
              </div>

              <p class="mt-5 text-sm font-light leading-6 text-[#6B7280]">
                Use your institutional account to access your LMS dashboard.
              </p>
            </div>

            <form class="space-y-4" @submit.prevent="handleLogin">
              <!-- Email -->
              <div class="space-y-1.5">
                <label class="block text-[11px] font-semibold uppercase tracking-wider text-[#1F2937]">
                  Email Address
                </label>

                <div
                  class="flex items-center rounded-[14px] border border-[#E7DCC3] bg-white px-4 py-3 shadow-[inset_0_1px_4px_rgba(128,0,0,0.04)] transition focus-within:border-[#800000] focus-within:ring-2 focus-within:ring-[#F6E7B2]"
                >
                  <MailIcon class="mr-3 h-4 w-4 shrink-0 text-[#800000]/70" />
                  <input
                    v-model="form.email"
                    type="email"
                    placeholder="you@msu.edu.ph"
                    class="w-full bg-transparent text-sm font-light text-[#1F2937] outline-none placeholder:text-[#9CA3AF]"
                  />
                </div>
              </div>

              <!-- Password -->
              <div class="space-y-1.5">
                <label class="block text-[11px] font-semibold uppercase tracking-wider text-[#1F2937]">
                  Password
                </label>

                <div
                  class="flex items-center rounded-[14px] border border-[#E7DCC3] bg-white px-4 py-3 shadow-[inset_0_1px_4px_rgba(128,0,0,0.04)] transition focus-within:border-[#800000] focus-within:ring-2 focus-within:ring-[#F6E7B2]"
                >
                  <LockIcon class="mr-3 h-4 w-4 shrink-0 text-[#800000]/70" />
                  <input
                    v-model="form.password"
                    :type="showPassword ? 'text' : 'password'"
                    placeholder="••••••••"
                    class="w-full bg-transparent text-sm font-light text-[#1F2937] outline-none placeholder:text-[#9CA3AF]"
                  />

                  <button
                    type="button"
                    @click="showPassword = !showPassword"
                    class="ml-3 text-[#6B7280] transition hover:text-[#800000]"
                  >
                    <EyeIcon v-if="!showPassword" class="h-4 w-4" />
                    <EyeOffIcon v-else class="h-4 w-4" />
                  </button>
                </div>
              </div>

              <!-- Error -->
              <p
                v-if="error"
                class="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-light text-red-600"
              >
                {{ error }}
              </p>

              <!-- Button -->
              <button
                type="submit"
                :disabled="isLoading"
                class="inline-flex w-full items-center justify-center gap-2 rounded-full bg-gradient-to-r from-[#800000] via-[#8F1111] to-[#5A0000] px-6 py-3.5 text-sm font-semibold text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.18),0_14px_28px_rgba(128,0,0,0.22)] transition hover:-translate-y-0.5 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.22),0_18px_34px_rgba(128,0,0,0.28)] disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:translate-y-0"
              >
                <LogInIcon class="h-4 w-4" />
                {{ isLoading ? 'Signing in...' : 'Sign In' }}
              </button>
            </form>

            <p class="mt-6 border-t border-[#E7DCC3] pt-5 text-center text-xs font-light text-[#6B7280]">
              MSU LMS &copy; {{ new Date().getFullYear() }} · Mindanao State University
            </p>
          </div>
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
import msuSeal from '@/assets/msu-seal.png'
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

<style scoped>
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap');

.login-page {
  font-family: 'Poppins', sans-serif;
}
</style>