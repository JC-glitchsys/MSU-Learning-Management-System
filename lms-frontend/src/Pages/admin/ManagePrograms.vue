<template>
  <div class="space-y-6 animate-fade-in">
    <!-- Header -->
    <section
      class="flex items-end justify-between gap-6 border-b border-[#DADCE0] pb-5"
    >
      <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p class="text-xs font-medium text-[#5F6368]">
            Administration / Programs
          </p>

          <h1 class="mt-1 text-2xl font-semibold tracking-tight text-[#202124]">
            Manage Programs
          </h1>

          <p class="mt-1 max-w-2xl text-sm font-medium text-[#5F6368]">
            Add, update, search, and manage academic degree programs.
          </p>
        </div>

        <button
          @click="openModal()"
          class="inline-flex h-10 w-fit items-center justify-center gap-2 rounded-lg bg-[#800000] px-4 text-sm font-medium text-white transition hover:bg-[#5C0000]"
        >
          <PlusCircleIcon class="h-4 w-4" />
          Add Program
        </button>
      </div>
    </section>

    <!-- Search -->
    <section
      class="flex flex-col justify-between gap-4 border-b border-[#DADCE0] pb-4 md:flex-row md:items-center"
    >
      <div
        class="flex h-10 w-full items-center rounded-lg border border-[#DADCE0] bg-white px-3 transition focus-within:border-[#800000] md:max-w-lg"
      >
        <SearchIcon class="mr-2 h-4 w-4 shrink-0 text-[#800000]/70" />
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search by program code, title, or department..."
          class="w-full bg-transparent text-sm font-medium text-[#202124] outline-none placeholder:text-[#5F6368]"
        />
      </div>

      <div
        class="inline-flex w-fit rounded-md bg-[#F8F9FA] px-2.5 py-1.5 text-xs font-medium text-[#5F6368]"
      >
        {{ filteredPrograms.length }} program{{ filteredPrograms.length === 1 ? '' : 's' }}
      </div>
      <ArchiveViewToggle v-model="showArchived" :active-count="activeCount" :archived-count="archivedCount" />
    </section>

    <!-- Main Card -->
    <section class="overflow-hidden rounded-lg border border-[#DADCE0] bg-white">
      <!-- Loading -->
      <div v-if="loading" class="p-12 text-center">
        <span
          class="inline-block h-7 w-7 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"
        ></span>
        <p class="mt-3 text-sm font-bold text-[#5F6368]">
          Loading academic programs...
        </p>
      </div>

      <!-- Error -->
      <div v-else-if="error" class="p-12 text-center">
        <AlertCircleIcon class="mx-auto h-10 w-10 text-[#D93025]" />
        <p class="mt-3 text-sm font-bold text-[#D93025]">
          {{ error }}
        </p>
      </div>

      <!-- Empty -->
      <div v-else-if="filteredPrograms.length === 0" class="p-12 text-center">
        <div
          class="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-[#FDF0F0] text-[#800000]"
        >
          <FolderIcon class="h-7 w-7" />
        </div>

        <h2 class="mt-4 text-lg font-black text-[#202124]">
          No programs found
        </h2>

        <p class="mt-1 text-sm text-[#5F6368]">
          Add a program or adjust your search keyword.
        </p>
      </div>

      <!-- Responsive Program List -->
      <div v-else class="divide-y divide-[#DADCE0]/70">
        <!-- Desktop Header -->
        <div
          class="hidden grid-cols-12 gap-4 bg-[#F8F9FA] px-6 py-4 text-xs font-black uppercase tracking-wider text-[#5F6368] lg:grid"
        >
          <div class="col-span-3">Program Code</div>
          <div class="col-span-4">Program Name</div>
          <div class="col-span-3">Department</div>
          <div class="col-span-2 text-right">Actions</div>
        </div>

        <div
          v-for="program in filteredPrograms"
          :key="program.id"
          class="grid grid-cols-1 gap-4 px-6 py-5 transition hover:bg-[#F8F9FA] lg:grid-cols-12 lg:items-center"
        >
          <!-- Program Code -->
          <div class="min-w-0 lg:col-span-3">
            <div class="flex items-center gap-3">
              <div
                class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[#800000] to-[#5C0000] text-xs font-black text-white ring-2 ring-[#FDF0F0]/40"
              >
                {{ getProgramInitials(program.programCode) }}
              </div>

              <div class="min-w-0">
                <p class="truncate text-sm font-black text-[#800000]">
                  {{ program.programCode || 'No Code' }}
                </p>
                <p class="mt-0.5 truncate text-xs font-medium text-[#5F6368]">
                  Academic Program
                </p>
              </div>
            </div>
          </div>

          <!-- Program Name -->
          <div class="min-w-0 lg:col-span-4">
            <p class="text-[10px] font-bold uppercase tracking-wider text-[#5F6368] lg:hidden">
              Program Name
            </p>

            <p class="mt-1 truncate text-sm font-black text-[#202124] lg:mt-0">
              {{ program.programName || 'Untitled Program' }}
            </p>

            <p class="mt-0.5 line-clamp-2 text-xs text-[#5F6368]">
              {{ program.description || 'No description provided.' }}
            </p>
          </div>

          <!-- Department -->
          <div class="min-w-0 lg:col-span-3">
            <p class="text-[10px] font-bold uppercase tracking-wider text-[#5F6368] lg:hidden">
              Department
            </p>

            <span
              class="mt-1 inline-flex max-w-full rounded-full border border-[#DADCE0] bg-[#FDF0F0] px-3 py-1 text-xs font-bold text-[#800000] lg:mt-0"
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
              class="inline-flex flex-1 items-center justify-center gap-2 rounded-full border border-[#DADCE0] bg-white px-4 py-2 text-xs font-black text-[#800000] shadow-sm transition hover:bg-[#800000] hover:text-white lg:flex-none"
            >
              <PencilIcon class="h-3.5 w-3.5" />
              Edit
            </button>

            <button
              @click="archiveProgram(program.id)"
              class="inline-flex h-9 flex-1 items-center justify-center gap-2 rounded-md border border-[#DADCE0] bg-white px-3 text-xs font-medium text-[#5F6368] transition hover:bg-[#F8F9FA] hover:text-[#202124] lg:flex-none"
            >
              <component :is="program.archived ? ArchiveRestoreIcon : ArchiveIcon" class="h-3.5 w-3.5" />
              {{ program.archived ? 'Restore' : 'Archive' }}
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
        class="w-full max-w-xl overflow-hidden rounded-lg border border-[#DADCE0] bg-white animate-slide-up"
      >
        <div
          class="flex items-center justify-between border-b border-[#DADCE0] bg-white px-6 py-5"
        >
          <div>
            <h3 class="text-lg font-black text-[#800000]">
              {{ isEditing ? 'Edit Program' : 'Add Program' }}
            </h3>
            <p class="mt-1 text-xs text-[#5F6368]">
              Fill in the academic program details below.
            </p>
          </div>

          <button
            @click="closeModal"
            class="rounded-full p-2 text-[#5F6368] transition hover:bg-white hover:text-[#800000]"
          >
            <XIcon class="h-5 w-5" />
          </button>
        </div>

        <form @submit.prevent="saveProgram" class="space-y-4 p-6">
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div class="space-y-1.5">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#202124]">
                Program Code
              </label>
              <input
                v-model="formData.programCode"
                required
                type="text"
                placeholder="e.g. BSIT"
                class="w-full rounded-[12px] border border-[#DADCE0] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              />
            </div>

            <div class="space-y-1.5">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#202124]">
                Department / College
              </label>
              <input
                v-model="formData.department"
                required
                type="text"
                placeholder="e.g. CICS"
                class="w-full rounded-[12px] border border-[#DADCE0] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              />
            </div>

            <div class="space-y-1.5 sm:col-span-2">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#202124]">
                Program Full Title
              </label>
              <input
                v-model="formData.programName"
                required
                type="text"
                placeholder="e.g. Bachelor of Science in Information Technology"
                class="w-full rounded-[12px] border border-[#DADCE0] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              />
            </div>

            <div class="space-y-1.5 sm:col-span-2">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#202124]">
                Description
              </label>
              <textarea
                v-model="formData.description"
                rows="3"
                placeholder="Short program description..."
                class="w-full resize-none rounded-[12px] border border-[#DADCE0] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              ></textarea>
            </div>
          </div>

          <div class="mt-6 flex flex-col-reverse gap-3 border-t border-[#DADCE0] pt-5 sm:flex-row sm:justify-end">
            <button
              type="button"
              @click="closeModal"
              class="rounded-full border border-[#DADCE0] bg-white px-6 py-3 text-sm font-bold text-[#800000] transition hover:bg-[#FDF0F0]"
            >
              Cancel
            </button>

            <button
              type="submit"
              :disabled="saving"
              class="inline-flex items-center justify-center gap-2 rounded-full bg-[#800000] px-6 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-[#5C0000] disabled:cursor-not-allowed disabled:opacity-60"
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
  doc,
  getDocs,
  serverTimestamp,
  updateDoc,
} from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import { confirmAction, showResult } from '@/utils/resultMessage'
import { filterArchived, setRecordArchived } from '@/utils/archive'
import ArchiveViewToggle from '@/components/common/ArchiveViewToggle.vue'
import {
  ArchiveIcon,
  ArchiveRestoreIcon,
  AlertCircleIcon,
  FolderIcon,
  PencilIcon,
  PlusCircleIcon,
  SaveIcon,
  SearchIcon,
  XIcon,
} from 'lucide-vue-next'

const programs = ref([])
const loading = ref(true)
const saving = ref(false)
const error = ref('')
const searchQuery = ref('')
const showArchived = ref(false)
const isModalOpen = ref(false)
const isEditing = ref(false)
const currentId = ref(null)

const activeCount = computed(() => programs.value.filter((item) => item.archived !== true).length)
const archivedCount = computed(() => programs.value.filter((item) => item.archived === true).length)

const formData = ref({
  programCode: '',
  programName: '',
  department: '',
  description: '',
})

const filteredPrograms = computed(() => {
  const queryText = searchQuery.value.toLowerCase().trim()

  const visible = filterArchived(programs.value, showArchived.value)
  if (!queryText) return visible

  return visible.filter((program) => {
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

  //Create and Update Operation//
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
    showResult(isEditing.value ? 'Program Updated' : 'Program Added', 'The academic program has been saved.')
  } catch (err) {
    console.error('Save program error:', err)
    showResult('Could Not Save Program', 'Please try again.', 'error')
  } finally {
    saving.value = false
  }
}

async function archiveProgram(id) {
  const program = programs.value.find((item) => item.id === id)
  const restoring = program?.archived === true
  if (!await confirmAction(restoring ? 'Restore Program?' : 'Archive Program?', restoring ? 'This program will return to the active list.' : 'This program will be archived and can be restored later.', restoring ? 'Restore' : 'Archive')) return

  try {
    await setRecordArchived(db, 'programs', id, !restoring)
    await fetchPrograms()
    showResult(restoring ? 'Program Restored' : 'Program Archived', restoring ? 'The program is active again.' : 'The program was moved to the archive.')
  } catch (err) {
    console.error('Archive program error:', err)
    showResult('Could Not Update Program', 'Please try again.', 'error')
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
