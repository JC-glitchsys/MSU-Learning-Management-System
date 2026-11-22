<template>
  <div class="space-y-6 animate-fade-in">
    <!-- Header -->
    <section
      class="flex items-end justify-between gap-6 border-b border-[#DADCE0] pb-5"
    >
      <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p class="text-xs font-medium text-[#5F6368]">Administration / Instructors</p>

          <h1 class="mt-1 text-2xl font-semibold tracking-tight text-[#202124]">
            Manage Instructors
          </h1>

          <p class="mt-1 max-w-2xl text-sm font-normal text-[#5F6368]">
            Add, update, search, and manage instructor profiles stored in Firestore.
          </p>
        </div>

        <button
          @click="openModal()"
          class="inline-flex h-10 w-fit items-center justify-center gap-2 rounded-lg bg-[#800000] px-4 text-sm font-medium text-white transition hover:bg-[#5C0000]"
        >
          <UserPlusIcon class="h-4 w-4" />
          Add Instructor
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
          placeholder="Search by name, email, faculty ID, or department..."
          class="w-full bg-transparent text-sm font-medium text-[#202124] outline-none placeholder:text-[#5F6368]"
        />
      </div>

      <div
        class="inline-flex w-fit rounded-md bg-[#F8F9FA] px-2.5 py-1.5 text-xs font-medium text-[#5F6368]"
      >
        {{ filteredInstructors.length }} instructor{{ filteredInstructors.length === 1 ? '' : 's' }}
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
          Loading instructor records...
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
      <div v-else-if="filteredInstructors.length === 0" class="p-12 text-center">
        <div
          class="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-[#FDF0F0] text-[#800000]"
        >
          <GraduationCapIcon class="h-7 w-7" />
        </div>

        <h2 class="mt-4 text-lg font-black text-[#202124]">
          No instructors found
        </h2>

        <p class="mt-1 text-sm text-[#5F6368]">
          Add an instructor or adjust your search keyword.
        </p>
      </div>

      <!-- Responsive Instructor List -->
      <div v-else class="divide-y divide-[#DADCE0]/70">
        <!-- Desktop Header -->
        <div
          class="hidden grid-cols-12 gap-4 border-b border-[#DADCE0] bg-[#F8F9FA] px-5 py-3 text-xs font-semibold uppercase tracking-wide text-[#5F6368] lg:grid"
        >
          <div class="col-span-4">Instructor</div>
          <div class="col-span-3">Department</div>
          <div class="col-span-3">Contact</div>
          <div class="col-span-2 text-right">Actions</div>
        </div>

        <div
          v-for="inst in filteredInstructors"
          :key="inst.id"
          class="grid grid-cols-1 gap-4 px-5 py-4 transition-colors hover:bg-[#F8F9FA] lg:grid-cols-12 lg:items-center"
        >
          <!-- Instructor -->
          <div class="min-w-0 lg:col-span-4">
            <div class="flex items-center gap-3">
              <div
                class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#FDF0F0] text-xs font-semibold text-[#800000]"
              >
                {{ getInitials(inst.name) }}
              </div>

              <div class="min-w-0">
                <p class="truncate text-sm font-semibold text-[#202124]">
                  {{ inst.name || 'Unnamed Instructor' }}
                </p>
                <p class="mt-0.5 truncate text-xs font-medium text-[#5F6368]">
                  Faculty ID: {{ inst.facultyId || 'N/A' }}
                </p>
              </div>
            </div>
          </div>

          <!-- Department -->
          <div class="min-w-0 lg:col-span-3">
            <p class="text-[10px] font-bold uppercase tracking-wider text-[#5F6368] lg:hidden">
              Department
            </p>

            <p class="mt-1 truncate text-sm font-black text-[#202124] lg:mt-0">
              {{ inst.department || 'Not assigned' }}
            </p>

            <p class="mt-0.5 truncate text-xs text-[#5F6368]">
              {{ inst.specialization || 'General specialization' }}
            </p>
          </div>

          <!-- Contact -->
          <div class="min-w-0 lg:col-span-3">
            <p class="text-[10px] font-bold uppercase tracking-wider text-[#5F6368] lg:hidden">
              Contact
            </p>

            <p class="mt-1 truncate text-xs font-semibold text-[#202124] lg:mt-0">
              {{ inst.email || 'No email' }}
            </p>

            <p class="mt-0.5 truncate text-xs text-[#5F6368]">
              {{ inst.contact || 'No contact number' }}
            </p>
          </div>

          <!-- Actions -->
          <div class="flex gap-2 lg:col-span-2 lg:justify-end">
            <button
              @click="openModal(inst)"
              class="inline-flex h-9 flex-1 items-center justify-center gap-2 rounded-md border border-[#DADCE0] bg-white px-3 text-xs font-medium text-[#202124] transition hover:border-[#B9BEC6] hover:bg-[#F8F9FA] lg:flex-none"
            >
              <PencilIcon class="h-3.5 w-3.5" />
              Edit
            </button>

            <button
              @click="archiveInstructor(inst.id)"
              class="inline-flex h-9 flex-1 items-center justify-center gap-2 rounded-md border border-[#E7C5C5] bg-white px-3 text-xs font-medium text-[#9F2424] transition hover:bg-[#FDF0F0] lg:flex-none"
            >
              <component :is="inst.archived ? ArchiveRestoreIcon : ArchiveIcon" class="h-3.5 w-3.5" />
              {{ inst.archived ? 'Restore' : 'Archive' }}
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
        class="w-full max-w-xl overflow-hidden rounded-[28px] border border-[#DADCE0] bg-white shadow-xl animate-slide-up"
      >
        <div
          class="flex items-center justify-between border-b border-[#DADCE0] bg-gradient-to-br from-white to-[#FDF0F0] px-6 py-5"
        >
          <div>
            <h3 class="text-lg font-black text-[#800000]">
              {{ isEditing ? 'Edit Instructor Profile' : 'Add Instructor' }}
            </h3>
            <p class="mt-1 text-xs text-[#5F6368]">
              Fill in the instructor information below.
            </p>
          </div>

          <button
            @click="closeModal"
            class="rounded-full p-2 text-[#5F6368] transition hover:bg-white hover:text-[#800000]"
          >
            <XIcon class="h-5 w-5" />
          </button>
        </div>

        <form @submit.prevent="saveInstructor" class="space-y-4 p-6">
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div class="space-y-1.5 sm:col-span-2">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#202124]">
                Full Name
              </label>
              <input
                v-model="formData.name"
                required
                type="text"
                placeholder="e.g. Prof. Jonaidah Caris"
                class="w-full rounded-[12px] border border-[#DADCE0] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              />
            </div>

            <div class="space-y-1.5 sm:col-span-2">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#202124]">
                Institutional Email
              </label>
              <input
                v-model="formData.email"
                required
                type="email"
                placeholder="instructor@msu.edu.ph"
                class="w-full rounded-[12px] border border-[#DADCE0] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              />
            </div>

            <div class="space-y-1.5">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#202124]">
                Faculty ID
              </label>
              <input
                v-model="formData.facultyId"
                required
                type="text"
                placeholder="e.g. FAC-001"
                class="w-full rounded-[12px] border border-[#DADCE0] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              />
            </div>

            <div class="space-y-1.5">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#202124]">
                Contact Number
              </label>
              <input
                v-model="formData.contact"
                type="text"
                placeholder="09xxxxxxxxx"
                class="w-full rounded-[12px] border border-[#DADCE0] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              />
            </div>

            <div class="space-y-1.5 sm:col-span-2">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#202124]">
                Department
              </label>
              <input
                v-model="formData.department"
                required
                type="text"
                placeholder="e.g. College of Information and Computing Sciences"
                class="w-full rounded-[12px] border border-[#DADCE0] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              />
            </div>

            <div class="space-y-1.5 sm:col-span-2">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#202124]">
                Specialization
              </label>
              <input
                v-model="formData.specialization"
                type="text"
                placeholder="e.g. Database Systems, Web Development"
                class="w-full rounded-[12px] border border-[#DADCE0] bg-white px-4 py-2.5 text-sm outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              />
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
              {{ saving ? 'Saving...' : isEditing ? 'Update Instructor' : 'Save Instructor' }}
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
  query,
  serverTimestamp,
  updateDoc,
  where,
} from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import { confirmAction, showResult } from '@/utils/resultMessage'
import { filterArchived, setRecordArchived } from '@/utils/archive'
import ArchiveViewToggle from '@/components/common/ArchiveViewToggle.vue'
import {
  ArchiveIcon,
  ArchiveRestoreIcon,
  AlertCircleIcon,
  GraduationCapIcon,
  PencilIcon,
  SaveIcon,
  SearchIcon,
  UserPlusIcon,
  XIcon,
} from 'lucide-vue-next'

const instructors = ref([])
const loading = ref(true)
const saving = ref(false)
const error = ref('')
const searchQuery = ref('')
const showArchived = ref(false)

const isModalOpen = ref(false)
const isEditing = ref(false)
const currentId = ref(null)

const activeCount = computed(() => instructors.value.filter((item) => item.archived !== true).length)
const archivedCount = computed(() => instructors.value.filter((item) => item.archived === true).length)

const formData = ref({
  name: '',
  email: '',
  facultyId: '',
  department: '',
  specialization: '',
  contact: '',
})

const filteredInstructors = computed(() => {
  const queryText = searchQuery.value.toLowerCase().trim()

  const visible = filterArchived(instructors.value, showArchived.value)
  if (!queryText) return visible

  return visible.filter((inst) => {
    return (
      inst.name?.toLowerCase().includes(queryText) ||
      inst.email?.toLowerCase().includes(queryText) ||
      inst.department?.toLowerCase().includes(queryText) ||
      inst.specialization?.toLowerCase().includes(queryText) ||
      String(inst.facultyId || '').toLowerCase().includes(queryText)
    )
  })
})

async function fetchInstructors() {
  loading.value = true
  error.value = ''

  try {
    const instructorQuery = query(
      collection(db, 'users'),
      where('role', '==', 'instructor')
    )

    const querySnapshot = await getDocs(instructorQuery)

    instructors.value = querySnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))
  } catch (err) {
    console.error('Fetch instructors error:', err)
    error.value = 'Failed to load instructors. Please check Firestore permissions.'
  } finally {
    loading.value = false
  }
}

function openModal(inst = null) {
  if (inst) {
    isEditing.value = true
    currentId.value = inst.id

    formData.value = {
      name: inst.name || '',
      email: inst.email || '',
      facultyId: inst.facultyId || '',
      department: inst.department || '',
      specialization: inst.specialization || '',
      contact: inst.contact || '',
    }
  } else {
    isEditing.value = false
    currentId.value = null

    formData.value = {
      name: '',
      email: '',
      facultyId: '',
      department: '',
      specialization: '',
      contact: '',
    }
  }

  isModalOpen.value = true
}

function closeModal() {
  isModalOpen.value = false
}

async function saveInstructor() {
  saving.value = true

  const payload = {
    name: formData.value.name.trim(),
    email: formData.value.email.trim(),
    facultyId: formData.value.facultyId.trim(),
    department: formData.value.department.trim(),
    specialization: formData.value.specialization.trim(),
    contact: formData.value.contact.trim(),
    role: 'instructor',
    updatedAt: serverTimestamp(),
  }

  try {
    if (isEditing.value && currentId.value) {
      await updateDoc(doc(db, 'users', currentId.value), payload)
    } else {
      await addDoc(collection(db, 'users'), {
        ...payload,
        createdAt: serverTimestamp(),
      })
    }

    closeModal()
    await fetchInstructors()
    showResult(isEditing.value ? 'Instructor Updated' : 'Instructor Added', 'The instructor profile has been saved.')
  } catch (err) {
    console.error('Save instructor error:', err)
    showResult('Could Not Save Instructor', 'Please try again.', 'error')
  } finally {
    saving.value = false
  }
}

async function archiveInstructor(id) {
  const inst = instructors.value.find((item) => item.id === id)
  const restoring = inst?.archived === true
  if (!await confirmAction(restoring ? 'Restore Instructor?' : 'Archive Instructor?', restoring ? 'This instructor profile will return to the active list.' : 'This instructor profile will be archived and can be restored later.', restoring ? 'Restore' : 'Archive')) return

  try {
    await setRecordArchived(db, 'users', id, !restoring)
    await fetchInstructors()
    showResult(restoring ? 'Instructor Restored' : 'Instructor Archived', restoring ? 'The instructor profile is active again.' : 'The instructor profile was moved to the archive.')
  } catch (err) {
    console.error('Archive instructor error:', err)
    showResult('Could Not Update Instructor', 'Please try again.', 'error')
  }
}

function getInitials(name) {
  if (!name) return 'IN'

  return name
    .split(' ')
    .filter(Boolean)
    .map((word) => word.charAt(0))
    .join('')
    .toUpperCase()
    .slice(0, 2)
}

onMounted(fetchInstructors)
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
