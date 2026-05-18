<template>
  <div class="w-full max-w-md">
    <div class="text-center mb-8">
      <div class="w-16 h-16 rounded-full bg-[#800000] flex items-center justify-center mx-auto mb-4">
        <span class="text-[#D4AF37] font-bold text-xl">MSU</span>
      </div>
      <h1 class="text-2xl font-bold text-[#800000]">Create an Account</h1>
      <p class="text-sm text-[#6B7280] mt-1">Mindanao State University LMS</p>
    </div>

    <form
      class="rounded-2xl border border-[#E7DCC3] bg-white shadow-sm p-8 space-y-4"
      @submit.prevent="handleRegister"
    >
      <div>
        <label class="block text-sm font-medium mb-1.5">Account Type</label>
        <select
          v-model="form.role"
          class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-[#FAFAF7] focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000]"
        >
          <option value="student">Student</option>
          <option value="instructor">Instructor</option>
        </select>
      </div>

      <div>
        <label class="block text-sm font-medium mb-1.5">Full Name</label>
        <input
          v-model="form.name"
          type="text"
          placeholder="Juan Dela Cruz"
          class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-[#FAFAF7] focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000]"
        />
      </div>

      <div>
        <label class="block text-sm font-medium mb-1.5">Email</label>
        <input
          v-model="form.email"
          type="email"
          placeholder="you@msu.edu.ph"
          class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-[#FAFAF7] focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000]"
        />
      </div>

      <div>
        <label class="block text-sm font-medium mb-1.5">Password</label>
        <input
          v-model="form.password"
          type="password"
          placeholder="Minimum 6 characters"
          class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-[#FAFAF7] focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000]"
        />
      </div>

      <div v-if="form.role === 'student'" class="space-y-4 rounded-xl border border-[#E7DCC3] bg-[#FFF8E7] p-4">
        <p class="text-sm font-semibold text-[#800000]">Student Details</p>

        <div>
          <label class="block text-sm font-medium mb-1.5">Student Number</label>
          <input
            v-model="form.studentNumber"
            type="text"
            placeholder="202227914"
            class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-white focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000]"
          />
        </div>

        <div>
          <label class="block text-sm font-medium mb-1.5">Program</label>
          <input
            v-model="form.program"
            type="text"
            placeholder="BS Information Technology"
            class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-white focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000]"
          />
        </div>

        <div>
          <label class="block text-sm font-medium mb-1.5">Year Level</label>
          <input
            v-model="form.yearLevel"
            type="text"
            placeholder="3rd Year"
            class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-white focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000]"
          />
        </div>
      </div>

      <div v-if="form.role === 'instructor'" class="space-y-4 rounded-xl border border-[#E7DCC3] bg-[#FFF8E7] p-4">
        <p class="text-sm font-semibold text-[#800000]">Instructor Details</p>

        <div>
          <label class="block text-sm font-medium mb-1.5">Department</label>
          <input
            v-model="form.department"
            type="text"
            placeholder="Computer Studies"
            class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-white focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000]"
          />
        </div>

        <div>
          <label class="block text-sm font-medium mb-1.5">Specialization</label>
          <input
            v-model="form.specialization"
            type="text"
            placeholder="Web Development"
            class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-white focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000]"
          />
        </div>
      </div>

      <p v-if="error" class="text-xs text-red-600">{{ error }}</p>
      <p v-if="success" class="text-xs text-green-700">{{ success }}</p>

      <button
        type="submit"
        :disabled="isLoading"
        class="w-full rounded-lg bg-[#800000] px-5 py-3 text-sm font-semibold text-white hover:bg-[#5A0000] transition disabled:cursor-not-allowed disabled:opacity-60"
      >
        {{ isLoading ? 'Creating Account...' : 'Register' }}
      </button>

      <p class="text-center text-xs text-[#6B7280]">
        Already have an account?
        <router-link to="/login" class="text-[#800000] font-medium hover:underline">Sign In</router-link>
      </p>
    </form>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { createUserWithEmailAndPassword, updateProfile } from 'firebase/auth'
import { doc, serverTimestamp, setDoc } from 'firebase/firestore'
import { auth, db } from '../../firebase/config.js'

const router = useRouter()

const isLoading = ref(false)
const error = ref('')
const success = ref('')

const form = reactive({
  role: 'student',
  name: '',
  email: '',
  password: '',
  studentNumber: '',
  program: '',
  yearLevel: '',
  department: '',
  specialization: '',
})

const getFirebaseErrorMessage = (code) => {
  if (code === 'auth/email-already-in-use') return 'This email is already registered.'
  if (code === 'auth/invalid-email') return 'Please enter a valid email address.'
  if (code === 'auth/weak-password') return 'Password must be at least 6 characters.'
  return 'Unable to create account. Please try again.'
}

const buildUserProfile = (uid) => ({
  uid,
  name: form.name.trim(),
  email: form.email.trim(),
  role: form.role,
  createdAt: serverTimestamp(),
  updatedAt: serverTimestamp(),
})

const buildStudentProfile = (uid) => ({
  uid,
  name: form.name.trim(),
  email: form.email.trim(),
  studentNumber: form.studentNumber.trim(),
  program: form.program.trim(),
  yearLevel: form.yearLevel.trim(),
  role: 'student',
  createdAt: serverTimestamp(),
  updatedAt: serverTimestamp(),
})

const buildInstructorProfile = (uid) => ({
  uid,
  name: form.name.trim(),
  email: form.email.trim(),
  department: form.department.trim(),
  specialization: form.specialization.trim(),
  role: 'instructor',
  createdAt: serverTimestamp(),
  updatedAt: serverTimestamp(),
})

const validateForm = () => {
  if (!form.name.trim() || !form.email.trim() || !form.password.trim()) {
    return 'Full Name, Email, and Password are required.'
  }

  if (form.password.length < 6) {
    return 'Password must be at least 6 characters.'
  }

  if (form.role === 'student' && !form.studentNumber.trim()) {
    return 'Student Number is required for student accounts.'
  }

  if (form.role === 'instructor' && !form.department.trim()) {
    return 'Department is required for instructor accounts.'
  }

  return ''
}

const handleRegister = async () => {
  error.value = ''
  success.value = ''

  const validationError = validateForm()

  if (validationError) {
    error.value = validationError
    return
  }

  isLoading.value = true

  try {
    const credential = await createUserWithEmailAndPassword(
      auth,
      form.email.trim(),
      form.password,
    )

    const { user } = credential

    await updateProfile(user, {
      displayName: form.name.trim(),
    })

    await setDoc(doc(db, 'users', user.uid), buildUserProfile(user.uid))

    if (form.role === 'student') {
      await setDoc(doc(db, 'students', user.uid), buildStudentProfile(user.uid))
    }

    if (form.role === 'instructor') {
      await setDoc(doc(db, 'instructors', user.uid), buildInstructorProfile(user.uid))
    }

    success.value = 'Account created successfully. Redirecting to sign in...'

    setTimeout(() => {
      router.push('/login')
    }, 900)
  } catch (firebaseError) {
    error.value = getFirebaseErrorMessage(firebaseError.code)
  } finally {
    isLoading.value = false
  }
}
</script>
