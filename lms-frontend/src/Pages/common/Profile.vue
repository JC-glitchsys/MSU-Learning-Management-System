<template>
  <div class="mx-auto max-w-5xl space-y-6 animate-fade-in">
    <header>
      <p class="text-xs font-medium uppercase tracking-wide text-[#8A8F98]">Account</p>
      <h1 class="mt-1 text-3xl font-semibold leading-[38px] text-[#202124]">Edit profile</h1>
      <p class="mt-2 text-sm leading-5 text-[#737983]">Update your account details and profile photo.</p>
    </header>

    <p v-if="error" class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">
      {{ error }}
    </p>

    <div v-if="loading" class="rounded-2xl border border-[#E7E9EE] bg-white p-8 text-sm text-[#737983]">
      Loading your profile...
    </div>

    <div v-else class="grid grid-cols-1 items-start gap-5 xl:grid-cols-[260px_minmax(0,740px)] xl:justify-center">
      <section class="rounded-2xl border border-[#E7E9EE] bg-white p-6 text-center">
        <div class="mx-auto flex h-28 w-28 items-center justify-center overflow-hidden rounded-full bg-[#FDF0F0] text-2xl font-semibold text-[#800000] ring-2 ring-[#F2D5D5]">
          <img v-if="avatarPreview" :src="avatarPreview" alt="Profile photo preview" class="h-full w-full object-cover" />
          <span v-else>{{ initials }}</span>
        </div>
        <h2 class="mt-4 truncate text-base font-semibold text-[#202124]">{{ form.name || 'Your name' }}</h2>
        <p class="mt-1 text-sm text-[#737983]">{{ roleLabel }}</p>
        <p class="mt-1 break-all text-xs text-[#8A8F98]">{{ form.email }}</p>

        <div class="mt-5 flex flex-col gap-2">
          <label class="inline-flex cursor-pointer items-center justify-center rounded-lg border border-[#E7E9EE] px-4 py-2.5 text-sm font-medium text-[#4B515B] transition hover:border-[#D8B7B7] hover:bg-[#FDF8F8] hover:text-[#800000]">
            {{ avatarPreview ? 'Change photo' : 'Add photo' }}
            <input ref="fileInput" type="file" accept="image/png,image/jpeg,image/webp" class="sr-only" @change="handleImageChange" />
          </label>
          <button v-if="avatarPreview" type="button" class="rounded-lg px-4 py-2 text-sm text-[#737983] hover:bg-[#F7F7F8]" @click="removePhoto">
            Remove photo
          </button>
          <p class="text-xs leading-4 text-[#8A8F98]">PNG, JPG, or WebP. Maximum size 5 MB.</p>
          <p v-if="imageError" class="text-xs text-red-700" role="alert">{{ imageError }}</p>
        </div>
      </section>

      <form class="rounded-2xl border border-[#E7E9EE] bg-white p-6" @submit.prevent="saveProfile">
        <div class="mb-6 border-b border-[#ECEEF1] pb-4">
          <h2 class="text-base font-semibold text-[#202124]">Personal information</h2>
          <p class="mt-1 text-sm text-[#737983]">Your email is managed by your sign-in account.</p>
        </div>

        <div class="grid grid-cols-1 gap-x-5 gap-y-5 md:grid-cols-2">
          <label class="flex flex-col gap-1.5">
            <span class="text-sm font-medium text-[#4B515B]">Full name</span>
            <input v-model.trim="form.name" required maxlength="100" autocomplete="name" class="h-11 w-full rounded-lg border border-[#E4E7EC] bg-white px-3 text-sm text-[#202124] outline-none focus:border-[#800000]" />
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-sm font-medium text-[#4B515B]">Email address</span>
            <input v-model="form.email" type="email" disabled class="h-11 w-full rounded-lg border border-[#E4E7EC] bg-[#F8F9FA] px-3 text-sm text-[#8A8F98]" />
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-sm font-medium text-[#4B515B]">Contact number</span>
            <input v-model.trim="form.contact" type="tel" autocomplete="tel" placeholder="Add a contact number" class="h-11 w-full rounded-lg border border-[#E4E7EC] bg-white px-3 text-sm text-[#202124] outline-none focus:border-[#800000]" />
          </label>

          <template v-if="role === 'student'">
            <label class="flex flex-col gap-1.5">
              <span class="text-sm font-medium text-[#4B515B]">Student number</span>
              <input v-model.trim="form.studentNumber" class="h-11 w-full rounded-lg border border-[#E4E7EC] bg-white px-3 text-sm text-[#202124] outline-none focus:border-[#800000]" />
            </label>
            <label class="flex flex-col gap-1.5">
              <span class="text-sm font-medium text-[#4B515B]">Program</span>
              <input v-model.trim="form.program" placeholder="Your academic program" class="h-11 w-full rounded-lg border border-[#E4E7EC] bg-white px-3 text-sm text-[#202124] outline-none focus:border-[#800000]" />
            </label>
            <label class="flex flex-col gap-1.5">
              <span class="text-sm font-medium text-[#4B515B]">Year level</span>
              <input v-model.trim="form.yearLevel" placeholder="Your current year level" class="h-11 w-full rounded-lg border border-[#E4E7EC] bg-white px-3 text-sm text-[#202124] outline-none focus:border-[#800000]" />
            </label>
          </template>

          <template v-else-if="role === 'instructor'">
            <label class="flex flex-col gap-1.5">
              <span class="text-sm font-medium text-[#4B515B]">Department</span>
              <input v-model.trim="form.department" placeholder="Your department" class="h-11 w-full rounded-lg border border-[#E4E7EC] bg-white px-3 text-sm text-[#202124] outline-none focus:border-[#800000]" />
            </label>
            <label class="flex flex-col gap-1.5">
              <span class="text-sm font-medium text-[#4B515B]">Specialization</span>
              <input v-model.trim="form.specialization" placeholder="Your specialization" class="h-11 w-full rounded-lg border border-[#E4E7EC] bg-white px-3 text-sm text-[#202124] outline-none focus:border-[#800000]" />
            </label>
            <label class="flex flex-col gap-1.5">
              <span class="text-sm font-medium text-[#4B515B]">Faculty ID</span>
              <input v-model.trim="form.facultyId" class="h-11 w-full rounded-lg border border-[#E4E7EC] bg-white px-3 text-sm text-[#202124] outline-none focus:border-[#800000]" />
            </label>
          </template>

          <label v-else class="flex flex-col gap-1.5">
            <span class="text-sm font-medium text-[#4B515B]">Department</span>
            <input v-model.trim="form.department" placeholder="Optional" class="h-11 w-full rounded-lg border border-[#E4E7EC] bg-white px-3 text-sm text-[#202124] outline-none focus:border-[#800000]" />
          </label>
        </div>

        <div class="mt-8 flex flex-wrap items-center justify-between gap-4 border-t border-[#ECEEF1] pt-5">
          <div v-if="saving" class="flex items-center gap-2 text-sm text-[#737983]" role="status" aria-live="polite">
            <LoaderCircle class="h-4 w-4 animate-spin text-[#800000]" />
            <span>{{ savingMessage }}</span>
          </div>
          <span v-else></span>
          <button type="submit" :disabled="saving" :aria-busy="saving" class="rounded-lg bg-[#800000] px-4 py-2.5 text-sm font-medium text-white transition hover:bg-[#5C0000] disabled:cursor-not-allowed disabled:opacity-60">
            <LoaderCircle v-if="saving" class="mr-2 inline-block h-4 w-4 animate-spin align-[-3px]" />
            {{ saving ? 'Saving...' : 'Save changes' }}
          </button>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { onAuthStateChanged, updateProfile } from 'firebase/auth'
import { doc, getDoc, serverTimestamp, writeBatch } from 'firebase/firestore'
import { getDownloadURL, ref as storageRef, uploadBytes } from 'firebase/storage'
import { LoaderCircle } from 'lucide-vue-next'
import { auth, db, storage } from '@/firebase/config.js'
import { showResult } from '@/utils/resultMessage'

const router = useRouter()
const loading = ref(true)
const saving = ref(false)
const savingMessage = ref('Saving profile...')
const error = ref('')
const imageError = ref('')
const fileInput = ref(null)
const photoURL = ref('')
const previewURL = ref('')
const selectedImage = ref(null)
const shouldRemovePhoto = ref(false)
const role = ref('student')
const uid = ref('')
const form = reactive({
  name: '', email: '', contact: '', studentNumber: '', program: '', yearLevel: '',
  department: '', specialization: '', facultyId: '',
})

const roleLabel = computed(() => ({ admin: 'Administrator', instructor: 'Instructor', student: 'Student' })[role.value] || 'Account')
const initials = computed(() => form.name.split(/\s+/).filter(Boolean).map((part) => part[0]).join('').slice(0, 2).toUpperCase() || 'U')
const avatarPreview = computed(() => previewURL.value || photoURL.value)

function getSessionUser() {
  try { return JSON.parse(localStorage.getItem('user') || '{}') } catch { return {} }
}

function waitForCurrentUser() {
  return new Promise((resolve) => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      unsubscribe()
      resolve(currentUser)
    })
  })
}

function loadProfile(primary, secondary = {}) {
  Object.assign(form, {
    name: primary.name || secondary.name || auth.currentUser?.displayName || '',
    email: primary.email || secondary.email || auth.currentUser?.email || '',
    contact: primary.contact || secondary.contact || '',
    studentNumber: secondary.studentNumber || primary.studentNumber || '',
    program: secondary.program || primary.program || '',
    yearLevel: secondary.yearLevel || primary.yearLevel || '',
    department: secondary.department || primary.department || '',
    specialization: secondary.specialization || primary.specialization || '',
    facultyId: secondary.facultyId || primary.facultyId || '',
  })
  photoURL.value = primary.photoURL || secondary.photoURL || getSessionUser().photoURL || ''
}

async function fetchProfile() {
  const session = getSessionUser()
  const currentUser = auth.currentUser || await waitForCurrentUser()
  uid.value = currentUser?.uid || session.uid || session.id || ''
  role.value = String(session.role || '').toLowerCase()

  if (!uid.value || !['admin', 'instructor', 'student'].includes(role.value)) {
    error.value = 'Could not identify your signed-in account. Please sign in again.'
    loading.value = false
    return
  }

  try {
    const userSnapshot = await getDoc(doc(db, 'users', uid.value))
    const primary = userSnapshot.exists() ? userSnapshot.data() : session
    let secondary = {}
    const collectionName = role.value === 'student' ? 'students' : role.value === 'instructor' ? 'instructors' : ''
    if (collectionName) {
      const roleSnapshot = await getDoc(doc(db, collectionName, uid.value))
      if (roleSnapshot.exists()) secondary = roleSnapshot.data()
    }
    loadProfile(primary, secondary)
  } catch (loadError) {
    console.error('Profile load failed:', loadError)
    error.value = 'Unable to load your profile. Please try again.'
  } finally {
    loading.value = false
  }
}

function handleImageChange(event) {
  imageError.value = ''
  const file = event.target.files?.[0]
  if (!file) return
  if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) {
    imageError.value = 'Choose a PNG, JPG, or WebP image.'
    selectedImage.value = null
    if (previewURL.value) URL.revokeObjectURL(previewURL.value)
    previewURL.value = ''
    event.target.value = ''
    return
  }
  if (file.size > 5 * 1024 * 1024) {
    imageError.value = 'The image must be 5 MB or smaller.'
    selectedImage.value = null
    if (previewURL.value) URL.revokeObjectURL(previewURL.value)
    previewURL.value = ''
    event.target.value = ''
    return
  }
  if (previewURL.value) URL.revokeObjectURL(previewURL.value)
  selectedImage.value = file
  previewURL.value = URL.createObjectURL(file)
  shouldRemovePhoto.value = false
}

function removePhoto() {
  imageError.value = ''
  if (previewURL.value) URL.revokeObjectURL(previewURL.value)
  previewURL.value = ''
  selectedImage.value = null
  photoURL.value = ''
  shouldRemovePhoto.value = true
  if (fileInput.value) fileInput.value.value = ''
}

async function saveProfile() {
  error.value = ''
  imageError.value = ''
  if (!form.name.trim()) {
    error.value = 'Enter your name before saving.'
    return
  }

  saving.value = true
  try {
    let nextPhotoURL = shouldRemovePhoto.value ? '' : photoURL.value
    if (selectedImage.value) {
      savingMessage.value = 'Uploading photo...'
      const extension = selectedImage.value.type.split('/')[1].replace('jpeg', 'jpg')
      const destination = storageRef(storage, `profile-images/${uid.value}/${Date.now()}.${extension}`)
      const uploaded = await uploadBytes(destination, selectedImage.value, { contentType: selectedImage.value.type })
      nextPhotoURL = await getDownloadURL(uploaded.ref)
    }
    savingMessage.value = 'Saving profile...'

    const currentUser = auth.currentUser

    const commonData = {
      uid: uid.value,
      email: form.email,
      role: role.value,
      name: form.name.trim(),
      contact: form.contact.trim(),
      photoURL: nextPhotoURL,
      updatedAt: serverTimestamp(),
      ...(role.value === 'admin' ? { department: form.department.trim() } : {}),
    }
    const batch = writeBatch(db)
    batch.set(doc(db, 'users', uid.value), commonData, { merge: true })

    if (role.value === 'student') {
      batch.set(doc(db, 'students', uid.value), {
        ...commonData,
        studentNumber: form.studentNumber.trim(),
        program: form.program.trim(),
        yearLevel: form.yearLevel.trim(),
      }, { merge: true })
    } else if (role.value === 'instructor') {
      batch.set(doc(db, 'instructors', uid.value), {
        ...commonData,
        department: form.department.trim(),
        specialization: form.specialization.trim(),
        facultyId: form.facultyId.trim(),
      }, { merge: true })
    }

    const persistenceTasks = [batch.commit()]
    if (currentUser) {
      persistenceTasks.push(updateProfile(currentUser, {
        displayName: form.name.trim(),
        photoURL: nextPhotoURL || null,
      }))
    }
    const persistenceResults = await Promise.allSettled(persistenceTasks)
    if (persistenceResults[0].status === 'rejected') throw persistenceResults[0].reason
    if (persistenceResults[1]?.status === 'rejected') {
      console.warn('Firebase Auth profile did not sync; Firestore profile was saved.', persistenceResults[1].reason)
    }
    photoURL.value = nextPhotoURL
    selectedImage.value = null
    shouldRemovePhoto.value = false
    if (previewURL.value) URL.revokeObjectURL(previewURL.value)
    previewURL.value = ''
    if (fileInput.value) fileInput.value.value = ''

    const session = getSessionUser()
    localStorage.setItem('user', JSON.stringify({ ...session, name: form.name.trim(), photoURL: nextPhotoURL }))
    window.dispatchEvent(new Event('lms:profile-updated'))
    showResult('Profile Updated', 'Your profile details and photo have been saved.')
  } catch (saveError) {
    console.error('Profile save failed:', saveError)
    error.value = saveError.code === 'storage/unauthorized'
      ? 'Photo upload is blocked by Firebase Storage rules. Update the Storage rules to allow signed-in users to upload their own profile photo.'
      : 'Unable to save your profile. Please try again.'
    showResult('Could Not Save Profile', error.value, 'error')
  } finally {
    saving.value = false
  }
}

onMounted(fetchProfile)
onBeforeUnmount(() => { if (previewURL.value) URL.revokeObjectURL(previewURL.value) })
</script>
