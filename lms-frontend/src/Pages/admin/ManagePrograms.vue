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
            Manage Programs
          </h1>

          <p class="mt-1 max-w-2xl text-sm font-medium text-[#6B7280]">
            Add, update, search, and manage academic degree programs.
          </p>
        </div>

        <button
          @click="openModal()"
          class="inline-flex w-fit items-center justify-center gap-2 rounded-full bg-[#800000] px-5 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-[#5A0000] hover:shadow-md"
        >
          <PlusCircleIcon class="h-4 w-4" />
          Add Program
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
          placeholder="Search by program code, title, or department..."
          class="w-full bg-transparent text-sm font-medium text-[#1F2937] outline-none placeholder:text-[#9CA3AF]"
        />
      </div>

      <div
        class="inline-flex w-fit rounded-full border border-[#E7DCC3] bg-[#FFF8E1] px-4 py-2 text-xs font-bold text-[#800000]"
      >
        {{ filteredPrograms.length }} program{{ filteredPrograms.length === 1 ? '' : 's' }}
      </div>
    </section>

    <!-- Main Card -->
    <section class="overflow-hidden rounded-[28px] border border-[#E7DCC3] bg-white shadow-sm">
      <!-- Loading -->
      <div v-if="loading" class="p-12 text-center">
        <span
          class="inline-block h-7 w-7 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"
        ></span>
        <p class="mt-3 text-sm font-bold text-[#6B7280]">
          Loading academic programs...
        </p>
      </div>

      <!-- Error -->
      <div v-else-if="error" class="p-12 text-center">
        <AlertCircleIcon class="mx-auto h-10 w-10 text-red-600" />
        <p class="mt-3 text-sm font-bold text-red-600">
          {{ error }}
        </p>
      </div>

      <!-- Empty -->
      <div v-else-if="filteredPrograms.length === 0" class="p-12 text-center">
        <div
          class="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-[#FFF8E1] text-[#800000]"
        >
          <FolderIcon class="h-7 w-7" />
        </div>

        <h2 class="mt-4 text-lg font-black text-[#1F2937]">
          No programs found
        </h2>

        <p class="mt-1 text-sm text-[#6B7280]">
          Add a program or adjust your search keyword.
        </p>
      </div>

      <!-- Responsive Program List -->
      <div v-else class="divide-y divide-[#E7DCC3]/70">
        <!-- Desktop Header -->
        <div
          class="hidden grid-cols-12 gap-4 bg-[#FAFAF7] px-6 py-4 text-xs font-black uppercase tracking-wider text-[#6B7280] lg:grid"
        >
          <div class="col-span-3">Program Code</div>
          <div class="col-span-4">Program Name</div>
          <div class="col-span-3">Department</div>
          <div class="col-span-2 text-right">Actions</div>
        </div>

        <div
          v-for="program in filteredPrograms"
          :key="program.id"
          class="grid grid-cols-1 gap-4 px-6 py-5 transition hover:bg-[#FAFAF7] lg:grid-cols-12 lg:items-center"
        >
          <!-- Program Code -->
          <div class="min-w-0 lg:col-span-3">
            <div class="flex items-center gap-3">
              <div
                class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[#800000] to-[#5A0000] text-xs font-black text-white ring-2 ring-[#D4AF37]/40"
              >
                {{ getProgramInitials(program.programCode) }}
              </div>

              <div class="min-w-0">
                <p class="truncate text-sm font-black text-[#800000]">
                  {{ program.programCode || 'No Code' }}
                </p>
                <p class="mt-0.5 truncate text-xs font-medium text-[#6B7280]">
                  Academic Program
                </p>
              </div>
            </div>
          </div>

          <!-- Program Name -->
          <div class="min-w-0 lg:col-span-4">
            <p class="text-[10px] font-bold uppercase tracking-wider text-[#6B7280] lg:hidden">
              Program Name
            </p>

            <p class="mt-1 truncate text-sm font-black text-[#1F2937] lg:mt-0">
              {{ program.programName || 'Untitled Program' }}
            </p>

            <p class="mt-0.5 line-clamp-2 text-xs text-[#6B7280]">
              {{ program.description || 'No description provided.' }}
            </p>
          </div>

          <!-- Department -->
          <div class="min-w-0 lg:col-span-3">
            <p class="text-[10px] font-bold uppercase tracking-wider text-[#6B7280] lg:hidden">
              Department
            </p>

            <span
              class="mt-1 inline-flex max-w-full rounded-full border border-[#E7DCC3] bg-[#FFF8E1] px-3 py-1 text-xs font-bold text-[#800000] lg:mt-0"
            >
              <span class="truncate">
                {{ program.department || 'Not specified' }}
              </span>
            </span>
          </div>

          <!-- Actions -->
          <div class="flex gap-2 lg:col-span-2 lg:justify-end">
            <button
              @click="openModal(program)"
              class="inline-flex flex-1 items-center justify-center gap-2 rounded-full border border-[#E7DCC3] bg-white px-4 py-2 text-xs font-black text-[#800000] shadow-sm transition hover:bg-[#800000] hover:text-white lg:flex-none"
            >
              <PencilIcon class="h-3.5 w-3.5" />
              Edit
            </button>

            <button
              @click="deleteProgram(program.id)"
              class="inline-flex flex-1 items-center justify-center gap-2 rounded-full border border-red-200 bg-red-50 px-4 py-2 text-xs font-black text-red-600 shadow-sm transition hover:bg-red-600 hover:text-white lg:flex-none"
            >
              <Trash2Icon class="h-3.5 w-3.5" />
              Delete
            </button>
          </div>
        </div>
      </div>
    </section>

    <!-- Modal -->
    <div
      v-if="isModalOpen"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 backdrop-blur-sm"
    >
      <div
        class="w-full max-w-xl overflow-hidden rounded-[28px] border border-[#E7DCC3] bg-white shadow-xl animate-slide-up"
      >
        <div
          class="flex items-center justify-between border-b border-[#E7DCC3] bg-gradient-to-br from-white to-[#FFF8E1] px-6 py-5"
        >
          <div>
            <h3 class="text-lg font-black text-[#800000]">
              {{ isEditing ? 'Edit Program' : 'Add Program' }}
            </h3>
            <p class="mt-1 text-xs text-[#6B7280]">
              Fill in the academic program details below.
            </p>
          </div>

          <button
            @click="closeModal"
            class="rounded-full p-2 text-[#6B7280] transition hover:bg-white hover:text-[#800000]"
          >
            <XIcon class="h-5 w-5" />
          </button>
        </div>

        <form @submit.prevent="saveProgram" class="space-y-4 p-6">
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div class="space-y-1.5">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#1F2937]">
                Program Code
              </label>
              <input
                v-model="formData.programCode"
                required
                type="text"
                placeholder="e.g. BSIT"
                class="w-full rounded-[12px] border border-[#E7DCC3] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
              />
            </div>

            <div class="space-y-1.5">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#1F2937]">
                Department / College
              </label>
              <input
                v-model="formData.department"
                required
                type="text"
                placeholder="e.g. CICS"
                class="w-full rounded-[12px] border border-[#E7DCC3] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
              />
            </div>

            <div class="space-y-1.5 sm:col-span-2">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#1F2937]">
                Program Full Title
              </label>
              <input
                v-model="formData.programName"
                required
                type="text"
                placeholder="e.g. Bachelor of Science in Information Technology"
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
                placeholder="Short program description..."
                class="w-full resize-none rounded-[12px] border border-[#E7DCC3] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
              ></textarea>
            </div>
          </div>

          <div class="mt-6 flex flex-col-reverse gap-3 border-t border-[#E7DCC3] pt-5 sm:flex-row sm:justify-end">
            <button
              type="button"
              @click="closeModal"
              class="rounded-full border border-[#E7DCC3] bg-white px-6 py-3 text-sm font-bold text-[#800000] transition hover:bg-[#FFF8E1]"
            >
              Cancel
            </button>

            <button
              type="submit"
              :disabled="saving"
              class="inline-flex items-center justify-center gap-2 rounded-full bg-[#800000] px-6 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-[#5A0000] disabled:cursor-not-allowed disabled:opacity-60"
            >
              <SaveIcon class="h-4 w-4" />
              {{ saving ? 'Saving...' : isEditing ? 'Update Program' : 'Save Program' }}
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
  serverTimestamp,
  updateDoc,
} from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import {
  AlertCircleIcon,
  FolderIcon,
  PencilIcon,
  PlusCircleIcon,
  SaveIcon,
  SearchIcon,
  Trash2Icon,
  XIcon,
} from 'lucide-vue-next'

const programs = ref([])
const loading = ref(true)
const saving = ref(false)
const error = ref('')
const searchQuery = ref('')
const isModalOpen = ref(false)
const isEditing = ref(false)
const currentId = ref(null)

const formData = ref({
  programCode: '',
  programName: '',
  department: '',
  description: '',
})

const filteredPrograms = computed(() => {
  const queryText = searchQuery.value.toLowerCase().trim()

  if (!queryText) return programs.value

  return programs.value.filter((program) => {
    return (
      program.programCode?.toLowerCase().includes(queryText) ||
      program.programName?.toLowerCase().includes(queryText) ||
      program.department?.toLowerCase().includes(queryText) ||
      program.description?.toLowerCase().includes(queryText)
    )
  })
})

async function fetchPrograms() {
  loading.value = true
  error.value = ''

  try {
    const snap = await getDocs(collection(db, 'programs'))

    programs.value = snap.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))
  } catch (err) {
    console.error('Fetch programs error:', err)
    error.value = 'Failed to load academic programs. Please check Firestore permissions.'
  } finally {
    loading.value = false
  }
}

function openModal(program = null) {
  if (program) {
    isEditing.value = true
    currentId.value = program.id

    formData.value = {
      programCode: program.programCode || '',
      programName: program.programName || '',
      department: program.department || '',
      description: program.description || '',
    }
  } else {
    isEditing.value = false
    currentId.value = null

    formData.value = {
      programCode: '',
      programName: '',
      department: '',
      description: '',
    }
  }

  isModalOpen.value = true
}

function closeModal() {
  isModalOpen.value = false
}

async function saveProgram() {
  saving.value = true

  const payload = {
    programCode: formData.value.programCode.trim(),
    programName: formData.value.programName.trim(),
    department: formData.value.department.trim(),
    description: formData.value.description.trim(),
    updatedAt: serverTimestamp(),
  }

  try {
    if (isEditing.value && currentId.value) {
      await updateDoc(doc(db, 'programs', currentId.value), payload)
    } else {
      await addDoc(collection(db, 'programs'), {
        ...payload,
        createdAt: serverTimestamp(),
      })
    }

    closeModal()
    await fetchPrograms()
  } catch (err) {
    console.error('Save program error:', err)
    alert('Failed to save program record.')
  } finally {
    saving.value = false
  }
}

async function deleteProgram(id) {
  if (!confirm('Delete this academic program? This action cannot be undone.')) return

  try {
    await deleteDoc(doc(db, 'programs', id))
    await fetchPrograms()
  } catch (err) {
    console.error('Delete program error:', err)
    alert('Failed to delete program.')
  }
}

function getProgramInitials(code) {
  if (!code) return 'PR'

  return String(code)
    .replace(/[^a-zA-Z]/g, '')
    .slice(0, 2)
    .toUpperCase() || 'PR'
}

onMounted(fetchPrograms)
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