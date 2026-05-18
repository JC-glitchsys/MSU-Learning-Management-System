<template>
  <div class="w-full max-w-md">
    <!-- Header -->
    <div class="text-center mb-8">
      <div class="w-16 h-16 rounded-full bg-[#800000] flex items-center justify-center mx-auto mb-4">
        <span class="text-[#D4AF37] font-bold text-xl">MSU</span>
      </div>
      <h1 class="text-2xl font-bold text-[#800000]">MSU Learning Management System</h1>
      <p class="text-sm text-[#6B7280] mt-1">Mindanao State University</p>
    </div>

    <!-- Card -->
    <form
      class="rounded-2xl border border-[#E7DCC3] bg-white shadow-sm p-8"
      @submit.prevent="handleLogin"
    >
      <h2 class="text-lg font-semibold text-[#1F1F1F] mb-6">Sign In to Your Account</h2>

      <div class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-[#1F1F1F] mb-1.5">Email Address</label>
          <input
            v-model="form.email"
            type="email"
            placeholder="you@msu.edu.ph"
            class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-[#FAFAF7] focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000] transition"
          />
        </div>
        <div>
          <label class="block text-sm font-medium text-[#1F1F1F] mb-1.5">Password</label>
          <input
            v-model="form.password"
            type="password"
            placeholder="••••••••"
            class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-[#FAFAF7] focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000] transition"
          />
        </div>

        <p v-if="error" class="text-xs text-red-600">{{ error }}</p>

        <button
          type="submit"
          :disabled="isLoading"
          class="w-full rounded-lg bg-[#800000] px-5 py-3 text-sm font-semibold text-white hover:bg-[#5A0000] transition mt-2 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {{ isLoading ? 'Signing In...' : 'Sign In' }}
        </button>

        <p class="text-center text-xs text-[#6B7280]">
          Need a student or instructor account?
          <router-link to="/register" class="text-[#800000] font-medium hover:underline">
            Register
          </router-link>
        </p>
      </div>
    </form>

    <p class="text-center text-xs text-[#6B7280] mt-6">
      MSU LMS &copy; {{ new Date().getFullYear() }} · Mindanao State University
    </p>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { signInWithEmailAndPassword } from 'firebase/auth'
import { doc, getDoc } from 'firebase/firestore'
import { auth, db } from '../../firebase/config.js'

const router = useRouter()
const error = ref('')
const isLoading = ref(false)
const form = ref({ email: '', password: '' })

const getDashboardByRole = (role) => {
  if (role === 'admin') return '/admin/dashboard'
  if (role === 'instructor') return '/instructor/dashboard'
  return '/student/dashboard'
}

const getFirebaseErrorMessage = (code) => {
  if (code === 'auth/invalid-email') return 'Please enter a valid email address.'
  if (code === 'auth/user-not-found') return 'No account found for this email.'
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
      form.value.password,
    )

    const userDoc = await getDoc(doc(db, 'users', credential.user.uid))

    if (!userDoc.exists()) {
      error.value = 'Account profile was not found in Firestore.'
      return
    }

    const profile = userDoc.data()
    const token = await credential.user.getIdToken()

    localStorage.setItem(
      'user',
      JSON.stringify({
        id: credential.user.uid,
        uid: credential.user.uid,
        name: profile.name || credential.user.displayName || credential.user.email,
        email: credential.user.email,
        role: profile.role || 'student',
        token,
      }),
    )

    router.push(getDashboardByRole(profile.role))
  } catch (firebaseError) {
    error.value = getFirebaseErrorMessage(firebaseError.code)
  } finally {
    isLoading.value = false
  }
}
</script>
