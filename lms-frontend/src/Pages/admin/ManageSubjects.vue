<template>
  <div class="space-y-6 animate-fade-in">
    <!-- Header -->
    <section
      class="rounded-[28px] border border-[#E7DCC3] bg-gradient-to-br from-white via-white to-[#FFF8E1] p-6 shadow-sm"
    >
      <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p class="text-xs font-bold uppercase tracking-[0.22em] text-[#D4AF37]">
            Admin Registry
          </p>

          <h1 class="mt-2 text-2xl font-black tracking-tight text-[#800000] md:text-3xl">
            Manage Subjects
          </h1>

          <p class="mt-1 max-w-2xl text-sm font-medium text-[#6B7280]">
            Add subjects, assign instructors, and connect each subject to an academic program.
          </p>
        </div>

        <button
          @click="openCreateModal"
          class="inline-flex w-fit items-center justify-center gap-2 rounded-full bg-[#800000] px-5 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-[#5A0000] hover:shadow-md"
        >
          <PlusCircleIcon class="h-4 w-4" />
          Add Subject
        </button>
      </div>
    </section>

    <!-- Search -->
    <section
      class="flex flex-col justify-between gap-4 rounded-[24px] border border-[#E7DCC3] bg-white p-4 shadow-sm md:flex-row md:items-center"
    >
      <div
        class="flex w-full items-center rounded-full border border-[#E7DCC3] bg-[#FAFAF7] px-4 py-2.5 transition focus-within:border-[#800000] focus-within:bg-white focus-within:ring-2 focus-within:ring-[#F6E7B2] md:max-w-md"
      >
        <SearchIcon class="mr-2 h-4 w-4 shrink-0 text-[#800000]/70" />
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search by code, title, section, program, or instructor..."
          class="w-full bg-transparent text-sm font-medium text-[#1F2937] outline-none placeholder:text-[#9CA3AF]"
        />
      </div>

      <div
        class="inline-flex w-fit rounded-full border border-[#E7DCC3] bg-[#FFF8E1] px-4 py-2 text-xs font-bold text-[#800000]"
      >
        {{ filteredSubjects.length }} subject{{ filteredSubjects.length === 1 ? '' : 's' }}
      </div>
    </section>

    <!-- Loading -->
    <section
      v-if="isLoading"
      class="rounded-[28px] border border-[#E7DCC3] bg-white p-12 text-center shadow-sm"
    >
      <span
        class="inline-block h-7 w-7 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"
      ></span>
      <p class="mt-3 text-sm font-bold text-[#6B7280]">Loading subjects...</p>
    </section>

    <!-- Error -->
    <section
      v-else-if="error"
      class="rounded-[28px] border border-red-200 bg-red-50 p-6 text-sm font-semibold text-red-600"
    >
      {{ error }}
    </section>

    <!-- Empty -->
    <section
      v-else-if="filteredSubjects.length === 0"
      class="rounded-[28px] border border-[#E7DCC3] bg-white p-12 text-center shadow-sm"
    >
      <div
        class="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-[#FFF8E1] text-[#800000]"
      >
        <BookOpenIcon class="h-7 w-7" />
      </div>

      <h2 class="mt-4 text-lg font-black text-[#1F2937]">
        No subjects found
      </h2>

      <p class="mt-1 text-sm text-[#6B7280]">
        Add a subject or adjust your search keyword.
      </p>
    </section>

    <!-- Subject Cards -->
    <section
      v-else
      class="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3"
    >
      <article
        v-for="subject in filteredSubjects"
        :key="subject.id"
        class="group overflow-hidden rounded-[26px] border border-[#E7DCC3] bg-white shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
      >
        <!-- Banner -->
        <div
          class="relative overflow-hidden bg-gradient-to-br from-[#800000] via-[#8F1111] to-[#D4AF37] p-5 text-white"
        >
          <div class="absolute -right-8 -top-8 h-24 w-24 rounded-full bg-white/10"></div>
          <div class="absolute -bottom-10 left-8 h-24 w-24 rounded-full bg-black/10"></div>

          <div class="relative flex items-start justify-between gap-3">
            <div class="min-w-0">
              <p class="text-xs font-bold uppercase tracking-[0.2em] text-white/70">
                {{ subject.code || 'No Code' }}
              </p>

              <h2 class="mt-2 truncate text-lg font-black">
                {{ subject.title || 'Untitled Subject' }}
              </h2>

              <p class="mt-1 truncate text-xs font-medium text-white/75">
                {{ subject.program || 'No program' }}
              </p>
            </div>

            <span
              class="shrink-0 rounded-full bg-white/15 px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-white ring-1 ring-white/20"
            >
              {{ subject.section || 'No Section' }}
            </span>
          </div>
        </div>

        <!-- Body -->
        <div class="space-y-4 p-5">
          <div class="rounded-2xl border border-[#E7DCC3] bg-[#FAFAF7] p-4">
            <div class="flex items-center gap-3">
              <div
                class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#FFF8E1] text-[#800000] ring-1 ring-[#E7DCC3]"
              >
                <GraduationCapIcon class="h-5 w-5" />
              </div>

              <div class="min-w-0">
                <p class="text-[10px] font-bold uppercase tracking-wider text-[#6B7280]">
                  Assigned Instructor
                </p>
                <p class="truncate text-sm font-black text-[#1F2937]">
                  {{ subject.instructorName || 'No instructor assigned' }}
                </p>
              </div>
            </div>
          </div>

          <p class="line-clamp-2 min-h-[40px] text-sm leading-relaxed text-[#6B7280]">
            {{ subject.description || 'No description provided.' }}
          </p>

          <div class="flex gap-2 pt-1">
            <button
              @click="openEditModal(subject)"
              class="inline-flex flex-1 items-center justify-center gap-2 rounded-full border border-[#E7DCC3] bg-white px-4 py-2 text-xs font-black text-[#800000] shadow-sm transition hover:bg-[#800000] hover:text-white"
            >
              <PencilIcon class="h-3.5 w-3.5" />
              Edit
            </button>

            <button
              @click="deleteSubject(subject.id)"
              class="inline-flex flex-1 items-center justify-center gap-2 rounded-full border border-red-200 bg-red-50 px-4 py-2 text-xs font-black text-red-600 shadow-sm transition hover:bg-red-600 hover:text-white"
            >
              <Trash2Icon class="h-3.5 w-3.5" />
              Delete
            </button>
          </div>
        </div>
      </article>
    </section>

    <!-- Modal -->
    <div
      v-if="showModal"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 backdrop-blur-sm"
    >
      <div
        class="w-full max-w-2xl overflow-hidden rounded-[28px] border border-[#E7DCC3] bg-white shadow-xl animate-slide-up"
      >
        <div
          class="flex items-center justify-between border-b border-[#E7DCC3] bg-gradient-to-br from-white to-[#FFF8E1] px-6 py-5"
        >
          <div>
            <h2 class="text-lg font-black text-[#800000]">
              {{ isEditing ? 'Edit Subject' : 'Add Subject' }}
            </h2>
            <p class="mt-1 text-xs text-[#6B7280]">
              Fill in the subject information and assign an instructor.
            </p>
          </div>

          <button
            @click="closeModal"
            class="rounded-full p-2 text-[#6B7280] transition hover:bg-white hover:text-[#800000]"
          >
            <XIcon class="h-5 w-5" />
          </button>
        </div>

        <form @submit.prevent="saveSubject" class="space-y-5 p-6">
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
                Academic Program
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
                rows="3"
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
                  {{ inst.name || inst.email }} ({{ inst.department || 'No Dept' }})
                </option>
              </select>

              <p
                v-if="availableInstructors.length === 0"
                class="mt-1 text-xs font-medium text-red-600"
              >
                No instructors found. Add instructor records first.
              </p>
            </div>
          </div>

          <div class="flex flex-col-reverse gap-3 border-t border-[#E7DCC3] pt-5 sm:flex-row sm:justify-end">
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
              class="inline-flex items-center justify-center gap-2 rounded-full bg-[#800000] px-6 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-[#5A0000] disabled:cursor-not-allowed disabled:opacity-60"
            >
              <SaveIcon class="h-4 w-4" />
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
  addDoc,
  collection,
  deleteDoc,
  doc,
  getDocs,
  query,
  serverTimestamp,
  updateDoc,
  where,
} from 'firebase/firestore'
import { db } from '@/firebase/config.js'
import {
  BookOpenIcon,
  GraduationCapIcon,
  PencilIcon,
  PlusCircleIcon,
  SaveIcon,
  SearchIcon,
  Trash2Icon,
  XIcon,
} from 'lucide-vue-next'

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
    console.error('Fetch subjects error:', err)
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
    console.error('Fetch instructors error:', err)
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
    console.error('Save subject error:', err)
    error.value = 'Unable to save subject.'
  } finally {
    isSaving.value = false
  }
}

async function deleteSubject(subjectId) {
  if (!confirm('Delete this subject? This action cannot be undone.')) return

  try {
    await deleteDoc(doc(db, 'subjects', subjectId))
    await fetchSubjects()
  } catch (err) {
    console.error('Delete subject error:', err)
    error.value = 'Unable to delete subject.'
  }
}
</script>

<style scoped>
.animate-fade-in {
  animation: fadeIn 0.22s ease-out forwards;
}

.animate-slide-up {
  animation: slideUp 0.22s ease-out forwards;
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(4px);
  }

  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@keyframes slideUp {
  from {
    opacity: 0;
    transform: translateY(12px);
  }

  to {
    opacity: 1;
    transform: translateY(0);
  }
}
</style>