<template>
  <div class="space-y-8 animate-fade-in">
    <!-- Error -->
    <div
      v-if="error"
      class="rounded-[24px] border border-[#DADCE0] bg-white p-5 text-sm font-semibold text-[#D93025]"
    >
      {{ error }}
    </div>

    <!-- Quick Tools -->
    <CardPanel title="Instructor Tools">
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <router-link
          v-for="tool in tools"
          :key="tool.to"
          :to="tool.to"
          class="group rounded-2xl border border-[#DADCE0] bg-white p-5 text-center shadow-sm transition hover:-translate-y-0.5 hover:border-[#800000] hover:shadow-md"
        >
          <div
            class="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-[#DADCE0] bg-[#FDF0F0] text-[#800000] transition group-hover:scale-105"
          >
            <component :is="tool.icon" class="h-5 w-5 stroke-[2]" />
          </div>

          <p class="mt-3 text-sm font-black text-[#202124] group-hover:text-[#800000]">
            {{ tool.label }}
          </p>

          <p class="mt-1 text-xs text-[#5F6368]">
            {{ tool.description }}
          </p>
        </router-link>
      </div>
    </CardPanel>

    <!-- Main Content -->
    <section class="grid grid-cols-1 gap-6 lg:grid-cols-2">
      <!-- Assigned Subjects -->
      <CardPanel title="Assigned Subjects">
        <template #header-action>
          <router-link
            to="/instructor/subjects"
            class="text-xs font-bold uppercase tracking-wide text-[#800000] hover:text-[#5C0000] hover:underline"
          >
            View All →
          </router-link>
        </template>

        <SkeletonLoader v-if="loading" variant="cards" />

        <div
          v-else-if="subjects.length === 0"
          class="rounded-2xl border border-dashed border-[#DADCE0] bg-[#F8F9FA] p-8 text-center"
        >
          <p class="text-sm font-bold text-[#202124]">No assigned subjects yet.</p>
          <p class="mt-1 text-xs text-[#5F6368]">
            Once the admin assigns a subject to you, it will appear here.
          </p>
        </div>

        <div v-else class="space-y-3.5">
          <router-link
            v-for="subject in subjects"
            :key="subject.id"
            to="/instructor/subjects"
            class="group block rounded-2xl border border-[#DADCE0] bg-white p-4 transition hover:border-[#800000] hover:shadow-sm"
          >
            <div class="flex items-start justify-between gap-4">
              <div class="min-w-0">
                <p class="truncate text-sm font-black text-[#202124] group-hover:text-[#800000]">
                  {{ subject.code || 'No Code' }} — {{ subject.title || 'Untitled Subject' }}
                </p>

                <p class="mt-1 text-xs font-medium text-[#5F6368]">
                  {{ subject.program || 'No program' }} • {{ subject.section || 'No section' }}
                </p>
              </div>

              <span
                class="shrink-0 rounded-full border border-[#DADCE0] bg-[#FDF0F0] px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-[#800000]"
              >
                Active
              </span>
            </div>
          </router-link>
        </div>
      </CardPanel>

      <!-- Recent Submissions -->
      <CardPanel title="Recent Submissions">
        <template #header-action>
          <router-link
            to="/instructor/submissions"
            class="text-xs font-bold uppercase tracking-wide text-[#800000] hover:text-[#5C0000] hover:underline"
          >
            Open Queue →
          </router-link>
        </template>

        <SkeletonLoader v-if="loading" variant="rows" />

        <div
          v-else-if="recentSubmissions.length === 0"
          class="rounded-2xl border border-dashed border-[#DADCE0] bg-[#F8F9FA] p-8 text-center"
        >
          <p class="text-sm font-bold text-[#202124]">No submissions yet.</p>
          <p class="mt-1 text-xs text-[#5F6368]">
            Student submissions for your activities will appear here.
          </p>
        </div>

        <div v-else class="space-y-3.5">
          <div
            v-for="submission in recentSubmissions"
            :key="submission.id"
            class="rounded-2xl border border-[#DADCE0] bg-white p-4 transition hover:border-[#FDF0F0] hover:shadow-sm"
          >
            <div class="flex items-center justify-between gap-4">
              <div class="flex min-w-0 items-center gap-3">
                <div
                  class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#800000] text-xs font-black text-white"
                >
                  {{ getInitials(submission.studentName) }}
                </div>

                <div class="min-w-0">
                  <p class="truncate text-sm font-black text-[#202124]">
                    {{ submission.studentName || 'Student' }}
                  </p>

                  <p class="mt-0.5 truncate text-xs font-medium text-[#5F6368]">
                    {{ submission.activityTitle || 'Activity' }}
                    <span v-if="submission.subjectCode"> • {{ submission.subjectCode }}</span>
                  </p>
                </div>
              </div>

              <span
                :class="getStatusClass(submission.status)"
                class="shrink-0 rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-wider"
              >
                {{ submission.status || 'submitted' }}
              </span>
            </div>
          </div>
        </div>
      </CardPanel>
    </section>

    <!-- Activity Overview -->
    <CardPanel title="Created Activities">
      <template #header-action>
        <router-link
          to="/instructor/create-activity"
          class="text-xs font-bold uppercase tracking-wide text-[#800000] hover:text-[#5C0000] hover:underline"
        >
          Create Activity →
        </router-link>
      </template>

      <SkeletonLoader v-if="loading" variant="cards" />

      <div
        v-else-if="activities.length === 0"
        class="rounded-2xl border border-dashed border-[#DADCE0] bg-[#F8F9FA] p-8 text-center"
      >
        <p class="text-sm font-bold text-[#202124]">No activities created yet.</p>
        <p class="mt-1 text-xs text-[#5F6368]">
          Create an assignment or quiz for your assigned subjects.
        </p>
      </div>

      <div v-else class="overflow-x-auto">
        <table class="w-full min-w-[650px] text-sm">
          <thead>
            <tr
              class="border-b border-[#DADCE0] text-left text-xs font-bold uppercase tracking-wider text-[#5F6368]"
            >
              <th class="pb-4">Subject</th>
              <th class="pb-4">Activity</th>
              <th class="pb-4">Type</th>
              <th class="pb-4 text-right">Due Date</th>
            </tr>
          </thead>

          <tbody class="divide-y divide-[#DADCE0]/70">
            <tr
              v-for="activity in recentActivities"
              :key="activity.id"
              class="transition hover:bg-[#F8F9FA]"
            >
              <td class="py-4">
                <p class="font-black text-[#202124]">
                  {{ activity.subjectCode || 'Subject' }}
                </p>
                <p class="mt-0.5 text-xs text-[#5F6368]">
                  {{ activity.subjectTitle || 'No subject title' }}
                </p>
              </td>

              <td class="py-4 font-bold text-[#202124]">
                {{ activity.title || 'Untitled Activity' }}
              </td>

              <td class="py-4">
                <span
                  class="rounded-full border border-[#DADCE0] bg-[#FDF0F0] px-3 py-1 text-xs font-bold capitalize text-[#800000]"
                >
                  {{ activity.type || 'activity' }}
                </span>
              </td>

              <td class="py-4 text-right text-xs font-bold text-[#5F6368]">
                {{ formatDate(activity.dueDate) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </CardPanel>
  </div>
</template>

<script setup>
import SkeletonLoader from '@/components/common/SkeletonLoader.vue'
import { computed, onMounted, ref } from 'vue'
import { collection, getDocs, query, where } from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import CardPanel from '@/components/common/CardPanel.vue'
import {
  InboxIcon,
  PenToolIcon,
  TargetIcon,
  UploadCloudIcon,
} from 'lucide-vue-next'

const user = JSON.parse(localStorage.getItem('user') || '{}')

const loading = ref(true)
const error = ref('')

const subjects = ref([])
const modules = ref([])
const activities = ref([])
const submissions = ref([])

const tools = [
  {
    to: '/instructor/upload-module',
    label: 'Upload Module',
    description: 'Post learning materials',
    icon: UploadCloudIcon,
  },
  {
    to: '/instructor/create-activity',
    label: 'Create Activity',
    description: 'Create assignments or quizzes',
    icon: PenToolIcon,
  },
  {
    to: '/instructor/submissions',
    label: 'Review Submissions',
    description: 'Check student outputs',
    icon: InboxIcon,
  },
  {
    to: '/instructor/submissions',
    label: 'Grade Work',
    description: 'Evaluate and give feedback',
    icon: TargetIcon,
  },
]

const recentSubmissions = computed(() => {
  return submissions.value.slice(0, 5)
})

const recentActivities = computed(() => {
  return activities.value.slice(0, 5)
})

async function fetchInstructorDashboard() {
  if (!user.uid) {
    error.value = 'No logged-in instructor found. Please log in again.'
    loading.value = false
    return
  }

  loading.value = true
  error.value = ''

  try {
    const subjectsQuery = query(
      collection(db, 'subjects'),
      where('instructorId', '==', user.uid)
    )

    const subjectsSnapshot = await getDocs(subjectsQuery)

    subjects.value = subjectsSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    })).filter((subject) => subject.archived !== true)

    const subjectIds = subjects.value.map((subject) => subject.id)

    const modulesQuery = query(
      collection(db, 'modules'),
      where('createdBy', '==', user.uid)
    )

    const modulesSnapshot = await getDocs(modulesQuery)

    modules.value = modulesSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    })).filter((module) => module.archived !== true)

    const activitiesQuery = query(
      collection(db, 'activities'),
      where('createdBy', '==', user.uid)
    )

    const activitiesSnapshot = await getDocs(activitiesQuery)

    activities.value = activitiesSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    })).filter((activity) => activity.archived !== true)

    const activityIds = activities.value.map((activity) => activity.id)

    if (activityIds.length === 0) {
      submissions.value = []
      return
    }

    const submissionsSnapshot = await getDocs(collection(db, 'submissions'))

    submissions.value = submissionsSnapshot.docs
      .map((document) => ({
        id: document.id,
        ...document.data(),
      }))
      .filter((submission) => {
        return (
          activityIds.includes(submission.activityId) ||
          subjectIds.includes(submission.subjectId)
        )
      })
  } catch (err) {
    console.error('Failed to load instructor dashboard:', err)
    error.value = 'Unable to load instructor dashboard data. Please try again.'
  } finally {
    loading.value = false
  }
}

function getInitials(name) {
  if (!name) return 'ST'

  return name
    .split(' ')
    .map((word) => word.charAt(0))
    .join('')
    .slice(0, 2)
    .toUpperCase()
}

function formatDate(value) {
  if (!value) return 'No due date'

  if (typeof value === 'string') return value

  if (value?.toDate) {
    return value.toDate().toLocaleDateString()
  }

  return 'No due date'
}

function getStatusClass(status) {
  if (status === 'graded') {
    return 'border-[#DADCE0] bg-white text-[#188038]'
  }

  if (status === 'late') {
    return 'border-[#DADCE0] bg-white text-[#D93025]'
  }

  return 'border-[#DADCE0] bg-white text-[#D93025]'
}

onMounted(fetchInstructorDashboard)
</script>

<style scoped>
.animate-fade-in {
  animation: fadeIn 0.25s ease-out forwards;
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
</style>
