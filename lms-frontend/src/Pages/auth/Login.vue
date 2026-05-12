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
    <div class="rounded-2xl border border-[#E7DCC3] bg-white shadow-sm p-8">
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

        <!-- Demo role picker (remove in production) -->
        <div>
          <label class="block text-sm font-medium text-[#1F1F1F] mb-1.5">Role (Demo)</label>
          <select
            v-model="form.role"
            class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-[#FAFAF7] focus:outline-none focus:border-[#800000] transition"
          >
            <option value="student">Student</option>
            <option value="instructor">Instructor</option>
            <option value="admin">Admin</option>
          </select>
        </div>

        <p v-if="error" class="text-xs text-red-600">{{ error }}</p>

        <button
          @click="handleLogin"
          class="w-full rounded-lg bg-[#800000] px-5 py-3 text-sm font-semibold text-white hover:bg-[#5A0000] transition mt-2"
        >
          Sign In
        </button>
      </div>
    </div>

    <p class="text-center text-xs text-[#6B7280] mt-6">
      MSU LMS &copy; {{ new Date().getFullYear() }} · Mindanao State University
    </p>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const error = ref('')
const form = ref({ email: '', password: '', role: 'student' })

function handleLogin() {
  if (!form.value.email || !form.value.password) {
    error.value = 'Please fill in all fields.'
    return
  }
  // Demo login — replace with real API call
  const demoUser = {
    id: 1,
    name: form.value.role === 'admin' ? 'Admin User' : form.value.role === 'instructor' ? 'Prof. Santos' : 'Juan Dela Cruz',
    email: form.value.email,
    role: form.value.role,
    token: 'demo-token',
  }
  localStorage.setItem('user', JSON.stringify(demoUser))
  if (form.value.role === 'admin') router.push('/admin/dashboard')
  else if (form.value.role === 'instructor') router.push('/instructor/dashboard')
  else router.push('/student/dashboard')
}
</script>
