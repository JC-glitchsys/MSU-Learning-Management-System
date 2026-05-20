<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
      <div>
        <h1 class="text-3xl font-black tracking-tight text-[#800000]">
          Manage Subjects
        </h1>
        <p class="mt-1 text-sm font-medium text-[#6B7280]">
          Add, update, assign instructors, and manage LMS subjects.
        </p>
      </div>

      <button
        @click="openCreateModal"
        class="rounded-full bg-[#800000] px-6 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-[#5A0000] hover:shadow-md"
      >
        + Add Subject
      </button>
    </div>

    <!-- Search -->
    <div class="rounded-[28px] border border-[#E7DCC3] bg-white p-5 shadow-sm">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search by subject code, title, section, program, or instructor..."
        class="w-full rounded-[12px] border border-[#E7DCC3] bg-white px-4 py-3 text-sm outline-none transition hover:border-[#D4AF37] focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
      />
    </div>

    <!-- Loading -->
    <div
      v-if="isLoading"
      class="rounded-[28px] border border-[#E7DCC3] bg-white p-8 text-center text-sm font-semibold text-[#6B7280] shadow-sm"
    >
      Loading subjects...
    </div>

    <!-- Error -->
    <div
      v-else-if="error"
      class="rounded-[28px] border border-red-200 bg-red-50 p-5 text-sm font-semibold text-red-600"
    >
      {{ error }}
    </div>

    <!-- Empty -->
    <div
      v-else-if="filteredSubjects.length === 0"
      class="rounded-[28px] border border-[#E7DCC3] bg-white p-10 text-center shadow-sm"
    >
      <h2 class="text-lg font-bold text-[#1F2937]">No subjects found</h2>
      <p class="mt-1 text-sm text-[#6B7280]">
        Add your first subject to start building the LMS class structure.
      </p>
    </div>

    <!-- Subject Cards -->
    <div
      v-else
      class="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-3"
    >
      <div
        v-for="subject in filteredSubjects"
        :key="subject.id"
        class="overflow-hidden rounded-[24px] border border-[#E7DCC3] bg-white shadow-sm transition hover:-translate-y-1 hover:shadow-md"
      >
        <div class="bg-gradient-to-r from-[#800000] via-[#9A1B1B] to-[#D4AF37] p-5 text-white">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <p class="text-xs font-bold uppercase tracking-widest text-white/70">
                {{ subject.code || 'No Code' }}
              </p>
              <h2 class="mt-1 truncate text-lg font-black">
                {{ subject.title || 'Untitled Subject' }}
              </h2>
            </div>

            <span class="rounded-full bg-white/15 px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-white ring-1 ring-white/20">
              {{ subject.section || 'No Section' }}
            </span>
          </div>
        </div>

        <div class="space-y-4 p-5">
          <div>
            <p class="text-xs font-bold uppercase tracking-wider text-[#6B7280]">
              Program
            </p>
            <p class="mt-1 text-sm font-bold text-[#1F2937]">
              {{ subject.program || 'Not specified' }}
            </p>
          </div>

          <div>
            <p class="text-xs font-bold uppercase tracking-wider text-[#6B7280]">
              Assigned Instructor
            </p>
            <p class="mt-1 text-sm font-bold text-[#800000]">
              {{ subject.instructorName || 'No instructor assigned' }}
            </p>
          </div>

          <p class="line-clamp-2 text-sm text-[#6B7280]">
            {{ subject.description || 'No description provided.' }}
          </p>

          <div class="flex gap-2 pt-2">
            <button
              @click="openEditModal(subject)"
              class="flex-1 rounded-full border border-[#E7DCC3] bg-white px-4 py-2 text-xs font-bold text-[#800000] transition hover:bg-[#FFF8E1]"
            >
              Edit
            </button>

            <button
              @click="deleteSubject(subject.id)"
              class="flex-1 rounded-full border border-red-200 bg-red-50 px-4 py-2 text-xs font-bold text-red-600 transition hover:bg-red-100"
            >
              Delete
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Modal -->
    <div
      v-if="showModal"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4"
    >
      <div class="w-full max-w-2xl rounded-[28px] border border-[#E7DCC3] bg-white p-6 shadow-xl">
        <div class="mb-5 flex items-center justify-between">
          <div>
            <h2 class="text-xl font-black text-[#800000]">
              {{ isEditing ? 'Edit Subject' : 'Add Subject' }}
            </h2>
            <p class="text-sm text-[#6B7280]">
              Fill in the subject information and assign an instructor.
            </p>
          </div>

          <button
            @click="closeModal"
            class="rounded-full px-3 py-2 text-sm font-bold text-[#6B7280] transition hover:bg-[#FFF8E1] hover:text-[#800000]"
          >
            ✕
          </button>
        </div>

        <form @submit.prevent="saveSubject" class="space-y-5">
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div class="space-y-1.5">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#1F2937]">
                Subject Code
              </label>
              <input
                v-model="formData.code"
                required
                type="text"
                placeholder="e.g. ITE192"
                class="w-full rounded-[12px] border border-[#E7DCC3] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
              />
            </div>

            <div class="space-y-1.5">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#1F2937]">
                Section
              </label>
              <input
                v-model="formData.section"
                required
                type="text"
                placeholder="e.g. BSIT-4A"
                class="w-full rounded-[12px] border border-[#E7DCC3] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
              />
            </div>

            <div class="space-y-1.5 sm:col-span-2">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#1F2937]">
                Subject Title
              </label>
              <input
                v-model="formData.title"
                required
                type="text"
                placeholder="e.g. Capstone Project 2"
                class="w-full rounded-[12px] border border-[#E7DCC3] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
              />
            </div>

            <div class="space-y-1.5 sm:col-span-2">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#1F2937]">
                Under What Academic Program?
              </label>
              <input
                v-model="formData.program"
                required
                type="text"
                placeholder="e.g. BSIT"
                class="w-full rounded-[12px] border border-[#E7DCC3] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
              />
            </div>

            <div class="space-y-1.5 sm:col-span-2">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#1F2937]">
                Description
              </label>
              <textarea
                v-model="formData.description"
                rows="2"
                placeholder="Subject description..."
                class="w-full resize-none rounded-[12px] border border-[#E7DCC3] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
              ></textarea>
            </div>

            <div class="space-y-1.5 sm:col-span-2">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#1F2937]">
                Assign Instructor
              </label>
              <select
                v-model="formData.instructorId"
                required
                class="w-full cursor-pointer rounded-[12px] border border-[#E7DCC3] bg-white px-4 py-2.5 text-sm text-[#1F2937] outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
              >
                <option value="" disabled>Select an instructor...</option>
                <option
                  v-for="inst in availableInstructors"
                  :key="inst.id"
                  :value="inst.id"
                >
                  {{ inst.name }} ({{ inst.department || 'No Dept' }})
                </option>
              </select>
            </div>
          </div>

          <div class="flex flex-col-reverse gap-3 pt-2 sm:flex-row sm:justify-end">
            <button
              type="button"
              @click="closeModal"
              class="rounded-full border border-[#E7DCC3] bg-white px-6 py-3 text-sm font-bold text-[#800000] transition hover:bg-[#FFF8E1]"
            >
              Cancel
            </button>

            <button
              type="submit"
              :disabled="isSaving"
              class="rounded-full bg-[#800000] px-6 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-[#5A0000] disabled:cursor-not-allowed disabled:opacity-60"
            >
              {{ isSaving ? 'Saving...' : isEditing ? 'Update Subject' : 'Save Subject' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import {
  collection,
  query,
  where,
  getDocs,
  addDoc,
  doc,
  updateDoc,
  deleteDoc,
  serverTimestamp,
} from 'firebase/firestore'
import { db } from '@/firebase/config.js'

const subjects = ref([])
const availableInstructors = ref([])

const searchQuery = ref('')
const error = ref('')
const isLoading = ref(false)
const isSaving = ref(false)
const showModal = ref(false)
const isEditing = ref(false)
const editingId = ref(null)

const formData = ref({
  code: '',
  title: '',
  description: '',
  program: '',
  section: '',
  instructorId: '',
})

const filteredSubjects = computed(() => {
  const keyword = searchQuery.value.toLowerCase().trim()

  if (!keyword) return subjects.value

  return subjects.value.filter((subject) => {
    return [
      subject.code,
      subject.title,
      subject.description,
      subject.program,
      subject.section,
      subject.instructorName,
    ]
      .join(' ')
      .toLowerCase()
      .includes(keyword)
  })
})

onMounted(async () => {
  await Promise.all([fetchSubjects(), fetchInstructors()])
})

async function fetchSubjects() {
  isLoading.value = true
  error.value = ''

  try {
    const snapshot = await getDocs(collection(db, 'subjects'))

    subjects.value = snapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))
  } catch (err) {
    console.log('Fetch subjects error:', err)
    error.value = 'Unable to load subjects.'
  } finally {
    isLoading.value = false
  }
}

async function fetchInstructors() {
  try {
    const instructorsQuery = query(
      collection(db, 'users'),
      where('role', '==', 'instructor')
    )

    const snapshot = await getDocs(instructorsQuery)

    availableInstructors.value = snapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))
  } catch (err) {
    console.log('Fetch instructors error:', err)
    error.value = 'Unable to load instructors.'
  }
}

function openCreateModal() {
  resetForm()
  isEditing.value = false
  editingId.value = null
  showModal.value = true
}

function openEditModal(subject) {
  isEditing.value = true
  editingId.value = subject.id

  formData.value = {
    code: subject.code || '',
    title: subject.title || '',
    description: subject.description || '',
    program: subject.program || '',
    section: subject.section || '',
    instructorId: subject.instructorId || '',
  }

  showModal.value = true
}

function closeModal() {
  showModal.value = false
  resetForm()
}

function resetForm() {
  formData.value = {
    code: '',
    title: '',
    description: '',
    program: '',
    section: '',
    instructorId: '',
  }
}

async function saveSubject() {
  error.value = ''

  if (!formData.value.instructorId) {
    error.value = 'Please assign an instructor.'
    return
  }

  const selectedInstructor = availableInstructors.value.find(
    (inst) => inst.id === formData.value.instructorId
  )

  if (!selectedInstructor) {
    error.value = 'Selected instructor was not found.'
    return
  }

  isSaving.value = true

  const payload = {
    code: formData.value.code.trim(),
    title: formData.value.title.trim(),
    description: formData.value.description.trim(),
    program: formData.value.program.trim(),
    section: formData.value.section.trim(),
    instructorId: selectedInstructor.id,
    instructorName: selectedInstructor.name || selectedInstructor.email || 'Unnamed Instructor',
    updatedAt: serverTimestamp(),
  }

  try {
    if (isEditing.value && editingId.value) {
      await updateDoc(doc(db, 'subjects', editingId.value), payload)
    } else {
      await addDoc(collection(db, 'subjects'), {
        ...payload,
        createdAt: serverTimestamp(),
      })
    }

    await fetchSubjects()
    closeModal()
  } catch (err) {
    console.log('Save subject error:', err)
    error.value = 'Unable to save subject.'
  } finally {
    isSaving.value = false
  }
}

async function deleteSubject(subjectId) {
  const confirmed = confirm('Are you sure you want to delete this subject?')

  if (!confirmed) return

  try {
    await deleteDoc(doc(db, 'subjects', subjectId))
    await fetchSubjects()
  } catch (err) {
    console.log('Delete subject error:', err)
    error.value = 'Unable to delete subject.'
  }
}
</script>