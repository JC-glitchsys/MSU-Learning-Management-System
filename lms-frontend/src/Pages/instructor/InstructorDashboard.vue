<template>
  <div class="space-y-8 animate-fade-in">
    <!-- Header -->
    <section class="rounded-[28px] border border-[#E7DCC3] bg-white p-6 shadow-sm">
      <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <p class="text-xs font-bold uppercase tracking-[0.2em] text-[#D4AF37]">
            Instructor Dashboard
          </p>

          <h1 class="mt-2 text-2xl font-black tracking-tight text-[#800000] md:text-3xl">
            Good day, {{ user.name || 'Instructor' }}!
          </h1>

          <p class="mt-1 max-w-2xl text-sm font-medium text-[#6B7280]">
            Manage your assigned subjects, upload modules, create activities, and review student submissions.
          </p>
        </div>

        <div
          class="inline-flex w-fit items-center gap-2 rounded-full border border-[#E7DCC3] bg-[#FFF8E1] px-4 py-2 text-xs font-bold text-[#800000]"
        >
          <AwardIcon class="h-3.5 w-3.5 stroke-[2.5]" />
          <span>{{ user.department || 'Faculty Workspace' }}</span>
        </div>
      </div>
    </section>

    <!-- Stats -->
    <section class="grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard
        title="Assigned Subjects"
        :value="totalSubjects"
        description="Subjects assigned to you"
        :icon="BookOpenIcon"
        iconBg="#FFF8E1"
      />

      <StatCard
        title="Uploaded Modules"
        :value="totalModules"
        description="Learning materials posted"
        :icon="UploadCloudIcon"
        iconBg="#FFF8E1"
      />

      <StatCard
        title="Created Activities"
        :value="totalActivities"
        description="Assignments and quizzes"
        :icon="PenToolIcon"
        iconBg="#FFF8E1"
      />

      <StatCard
        title="Pending Reviews"
        :value="pendingReviews"
        description="Submissions waiting for grading"
        :icon="InboxIcon"
        iconBg="#FFF8E1"
      />
    </section>

    <!-- Error -->
    <div
      v-if="error"
      class="rounded-[24px] border border-red-200 bg-red-50 p-5 text-sm font-semibold text-red-600"
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
          class="group rounded-2xl border border-[#E7DCC3] bg-white p-5 text-center shadow-sm transition hover:-translate-y-0.5 hover:border-[#800000] hover:shadow-md"
        >
          <div
            class="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-[#E7DCC3] bg-[#FFF8E1] text-[#800000] transition group-hover:scale-105"
          >
            <component :is="tool.icon" class="h-5 w-5 stroke-[2]" />
          </div>

          <p class="mt-3 text-sm font-black text-[#1F2937] group-hover:text-[#800000]">
            {{ tool.label }}
          </p>

          <p class="mt-1 text-xs text-[#6B7280]">
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
            class="text-xs font-bold uppercase tracking-wide text-[#800000] hover:text-[#5A0000] hover:underline"
          >
            View All →
          </router-link>
        </template>

        <div v-if="loading" class="p-8 text-center">
          <span
            class="inline-block h-6 w-6 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"
          ></span>
          <p class="mt-3 text-xs font-bold text-[#6B7280]">Loading assigned subjects...</p>
        </div>

        <div
          v-else-if="subjects.length === 0"
          class="rounded-2xl border border-dashed border-[#E7DCC3] bg-[#FAFAF7] p-8 text-center"
        >
          <p class="text-sm font-bold text-[#1F2937]">No assigned subjects yet.</p>
          <p class="mt-1 text-xs text-[#6B7280]">
            Once the admin assigns a subject to you, it will appear here.
          </p>
        </div>

        <div v-else class="space-y-3.5">
          <router-link
            v-for="subject in subjects"
            :key="subject.id"
            to="/instructor/subjects"
            class="group block rounded-2xl border border-[#E7DCC3] bg-white p-4 transition hover:border-[#800000] hover:shadow-sm"
          >
            <div class="flex items-start justify-between gap-4">
              <div class="min-w-0">
                <p class="truncate text-sm font-black text-[#1F2937] group-hover:text-[#800000]">
                  {{ subject.code || 'No Code' }} — {{ subject.title || 'Untitled Subject' }}
                </p>

                <p class="mt-1 text-xs font-medium text-[#6B7280]">
                  {{ subject.program || 'No program' }} • {{ subject.section || 'No section' }}
                </p>
              </div>

              <span
                class="shrink-0 rounded-full border border-[#E7DCC3] bg-[#FFF8E1] px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-[#800000]"
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
            class="text-xs font-bold uppercase tracking-wide text-[#800000] hover:text-[#5A0000] hover:underline"
          >
            Open Queue →
          </router-link>
        </template>

        <div v-if="loading" class="p-8 text-center">
          <span
            class="inline-block h-6 w-6 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"
          ></span>
          <p class="mt-3 text-xs font-bold text-[#6B7280]">Loading submissions...</p>
        </div>

        <div
          v-else-if="recentSubmissions.length === 0"
          class="rounded-2xl border border-dashed border-[#E7DCC3] bg-[#FAFAF7] p-8 text-center"
        >
          <p class="text-sm font-bold text-[#1F2937]">No submissions yet.</p>
          <p class="mt-1 text-xs text-[#6B7280]">
            Student submissions for your activities will appear here.
          </p>
        </div>

        <div v-else class="space-y-3.5">
          <div
            v-for="submission in recentSubmissions"
            :key="submission.id"
            class="rounded-2xl border border-[#E7DCC3] bg-white p-4 transition hover:border-[#D4AF37] hover:shadow-sm"
          >
            <div class="flex items-center justify-between gap-4">
              <div class="flex min-w-0 items-center gap-3">
                <div
                  class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#800000] text-xs font-black text-white"
                >
                  {{ getInitials(submission.studentName) }}
                </div>

                <div class="min-w-0">
                  <p class="truncate text-sm font-black text-[#1F2937]">
                    {{ submission.studentName || 'Student' }}
                  </p>

                  <p class="mt-0.5 truncate text-xs font-medium text-[#6B7280]">
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
          class="text-xs font-bold uppercase tracking-wide text-[#800000] hover:text-[#5A0000] hover:underline"
        >
          Create Activity →
        </router-link>
      </template>

      <div v-if="loading" class="p-8 text-center">
        <span
          class="inline-block h-6 w-6 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"
        ></span>
        <p class="mt-3 text-xs font-bold text-[#6B7280]">Loading activities...</p>
      </div>

      <div
        v-else-if="activities.length === 0"
        class="rounded-2xl border border-dashed border-[#E7DCC3] bg-[#FAFAF7] p-8 text-center"
      >
        <p class="text-sm font-bold text-[#1F2937]">No activities created yet.</p>
        <p class="mt-1 text-xs text-[#6B7280]">
          Create an assignment or quiz for your assigned subjects.
        </p>
      </div>

      <div v-else class="overflow-x-auto">
        <table class="w-full min-w-[650px] text-sm">
          <thead>
            <tr
              class="border-b border-[#E7DCC3] text-left text-xs font-bold uppercase tracking-wider text-[#6B7280]"
            >
              <th class="pb-4">Subject</th>
              <th class="pb-4">Activity</th>
              <th class="pb-4">Type</th>
              <th class="pb-4 text-right">Due Date</th>
            </tr>
          </thead>

          <tbody class="divide-y divide-[#E7DCC3]/70">
            <tr
              v-for="activity in recentActivities"
              :key="activity.id"
              class="transition hover:bg-[#FAFAF7]"
            >
              <td class="py-4">
                <p class="font-black text-[#1F2937]">
                  {{ activity.subjectCode || 'Subject' }}
                </p>
                <p class="mt-0.5 text-xs text-[#6B7280]">
                  {{ activity.subjectTitle || 'No subject title' }}
                </p>
              </td>

              <td class="py-4 font-bold text-[#1F2937]">
                {{ activity.title || 'Untitled Activity' }}
              </td>

              <td class="py-4">
                <span
                  class="rounded-full border border-[#E7DCC3] bg-[#FFF8E1] px-3 py-1 text-xs font-bold capitalize text-[#800000]"
                >
                  {{ activity.type || 'activity' }}
                </span>
              </td>

              <td class="py-4 text-right text-xs font-bold text-[#6B7280]">
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
import { computed, onMounted, ref } from 'vue'
import { collection, getDocs, query, where } from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import StatCard from '@/components/common/StatCard.vue'
import CardPanel from '@/components/common/CardPanel.vue'
import {
  AwardIcon,
  BookOpenIcon,
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

const totalSubjects = computed(() => subjects.value.length)
const totalModules = computed(() => modules.value.length)
const totalActivities = computed(() => activities.value.length)

const pendingReviews = computed(() => {
  return submissions.value.filter((submission) => submission.status !== 'graded').length
})

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
    }))

    const subjectIds = subjects.value.map((subject) => subject.id)

    const modulesQuery = query(
      collection(db, 'modules'),
      where('createdBy', '==', user.uid)
    )

    const modulesSnapshot = await getDocs(modulesQuery)

    modules.value = modulesSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))

    const activitiesQuery = query(
      collection(db, 'activities'),
      where('createdBy', '==', user.uid)
    )

    const activitiesSnapshot = await getDocs(activitiesQuery)

    activities.value = activitiesSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))

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
    return 'border-green-200 bg-green-50 text-green-700'
  }

  if (status === 'late') {
    return 'border-red-200 bg-red-50 text-red-700'
  }

  return 'border-amber-200 bg-amber-50 text-amber-700'
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