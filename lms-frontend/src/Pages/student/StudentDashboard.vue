<template>
  <div class="space-y-8 animate-fade-in">
    <!-- Header -->
    <section
      class="rounded-[28px] border border-[#E7DCC3] bg-white p-6 shadow-sm"
    >
      <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <p class="text-xs font-bold uppercase tracking-[0.2em] text-[#D4AF37]">
            Student Dashboard
          </p>

          <h1 class="mt-2 text-2xl font-black tracking-tight text-[#800000] md:text-3xl">
            Welcome back, {{ user.name || 'Student' }}!
          </h1>

          <p class="mt-1 max-w-2xl text-sm font-medium text-[#6B7280]">
            View your enrolled subjects, pending activities, submitted works, and grades.
          </p>
        </div>

        <div
          class="inline-flex w-fit items-center gap-2 rounded-full border border-[#E7DCC3] bg-[#FFF8E1] px-4 py-2 text-xs font-bold text-[#800000]"
        >
          <CompassIcon class="h-3.5 w-3.5 stroke-[2.5]" />
          <span>Current Semester</span>
        </div>
      </div>
    </section>

    <!-- Stats -->
    <section class="grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard
        title="Enrolled Subjects"
        :value="totalSubjects"
        description="Subjects you are currently enrolled in"
        :icon="BookOpenIcon"
        iconBg="#FFF8E1"
      />

      <StatCard
        title="Pending Activities"
        :value="totalPending"
        description="Activities not yet submitted"
        :icon="FileTextIcon"
        iconBg="#FFF8E1"
      />

      <StatCard
        title="Submitted Works"
        :value="totalSubmitted"
        description="Activities you have submitted"
        :icon="CheckCircle2Icon"
        iconBg="#FFF8E1"
      />

      <StatCard
        title="Average Grade"
        :value="runningAverage + '%'"
        description="Based on graded submissions"
        :icon="BarChart3Icon"
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

    <!-- Main Grid -->
    <section class="grid grid-cols-1 gap-6 lg:grid-cols-12">
      <!-- My Classes -->
      <div class="lg:col-span-7">
        <CardPanel title="My Subjects">
          <template #header-action>
            <router-link
              to="/student/subjects"
              class="text-xs font-bold uppercase tracking-wide text-[#800000] hover:text-[#5A0000] hover:underline"
            >
              View All →
            </router-link>
          </template>

          <div v-if="loading" class="p-8 text-center">
            <span
              class="inline-block h-6 w-6 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"
            ></span>
            <p class="mt-3 text-xs font-bold text-[#6B7280]">Loading subjects...</p>
          </div>

          <div
            v-else-if="subjects.length === 0"
            class="rounded-2xl border border-dashed border-[#E7DCC3] bg-[#FAFAF7] p-8 text-center"
          >
            <p class="text-sm font-bold text-[#1F2937]">No enrolled subjects yet.</p>
            <p class="mt-1 text-xs text-[#6B7280]">
              Once the admin enrolls you in a subject, it will appear here.
            </p>
          </div>

          <div v-else class="grid grid-cols-1 gap-4">
            <router-link
              v-for="subject in subjects"
              :key="subject.id"
              :to="`/student/subjects/${subject.subjectId}`"
              class="group overflow-hidden rounded-[22px] border border-[#E7DCC3] bg-white shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
            >
              <div
                class="bg-gradient-to-r from-[#800000] via-[#9A1B1B] to-[#D4AF37] p-5 text-white"
              >
                <div class="flex items-start justify-between gap-4">
                  <div class="min-w-0">
                    <p class="text-xs font-bold uppercase tracking-widest text-white/75">
                      {{ subject.subjectCode || 'No Code' }}
                    </p>

                    <h2 class="mt-1 truncate text-lg font-black">
                      {{ subject.subjectTitle || 'Untitled Subject' }}
                    </h2>

                    <p class="mt-1 truncate text-xs font-medium text-white/75">
                      Instructor: {{ subject.instructorName || 'Not assigned' }}
                    </p>
                  </div>

                  <span
                    class="shrink-0 rounded-full bg-white/15 px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-white ring-1 ring-white/20"
                  >
                    Open
                  </span>
                </div>
              </div>

              <div class="flex items-center justify-between p-4">
                <div>
                  <p class="text-xs font-bold uppercase tracking-wider text-[#6B7280]">
                    Enrollment Status
                  </p>
                  <p class="mt-1 text-sm font-bold text-[#1F2937]">
                    Active
                  </p>
                </div>

                <span
                  class="rounded-full border border-[#E7DCC3] bg-[#FFF8E1] px-3 py-1 text-xs font-bold text-[#800000] transition group-hover:bg-[#800000] group-hover:text-white"
                >
                  Go to Class →
                </span>
              </div>
            </router-link>
          </div>
        </CardPanel>
      </div>

      <!-- Pending Activities -->
      <div class="lg:col-span-5">
        <CardPanel title="Pending Activities">
          <template #header-action>
            <router-link
              to="/student/activities"
              class="text-xs font-bold uppercase tracking-wide text-[#800000] hover:text-[#5A0000] hover:underline"
            >
              Open Tasks →
            </router-link>
          </template>

          <div v-if="loading" class="p-8 text-center">
            <span
              class="inline-block h-6 w-6 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"
            ></span>
            <p class="mt-3 text-xs font-bold text-[#6B7280]">Loading activities...</p>
          </div>

          <div
            v-else-if="pendingActivities.length === 0"
            class="rounded-2xl border border-dashed border-[#E7DCC3] bg-[#FAFAF7] p-8 text-center"
          >
            <p class="text-sm font-bold text-[#1F2937]">No pending activities.</p>
            <p class="mt-1 text-xs text-[#6B7280]">
              You are all caught up for now.
            </p>
          </div>

          <div v-else class="space-y-3.5">
            <div
              v-for="activity in pendingActivities"
              :key="activity.id"
              class="rounded-2xl border border-[#E7DCC3] bg-white p-4 transition hover:border-[#D4AF37] hover:shadow-sm"
            >
              <div class="flex items-start gap-3">
                <div
                  class="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#E7DCC3] bg-[#FFF8E1] text-[#800000]"
                >
                  <FileTextIcon class="h-4 w-4 stroke-[2]" />
                </div>

                <div class="min-w-0 flex-1">
                  <p class="truncate text-sm font-black text-[#1F2937]">
                    {{ activity.title || 'Untitled Activity' }}
                  </p>

                  <p class="mt-0.5 text-xs font-medium text-[#6B7280]">
                    {{ activity.subjectCode || 'Subject' }}
                    <span v-if="activity.points"> • {{ activity.points }} pts</span>
                  </p>

                  <p class="mt-2 line-clamp-2 text-xs text-[#6B7280]">
                    {{ activity.instructions || 'No instructions provided.' }}
                  </p>
                </div>
              </div>

              <div class="mt-4 flex items-center justify-between gap-3">
                <span
                  class="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-amber-700"
                >
                  Due: {{ formatDate(activity.dueDate) }}
                </span>

                <router-link
                  to="/student/activities"
                  class="text-xs font-bold text-[#800000] hover:underline"
                >
                  Submit →
                </router-link>
              </div>
            </div>
          </div>
        </CardPanel>
      </div>
    </section>

    <!-- Grades / Submissions -->
    <CardPanel title="Recent Submissions and Grades">
      <template #header-action>
        <router-link
          to="/student/grades"
          class="text-xs font-bold uppercase tracking-wide text-[#800000] hover:text-[#5A0000] hover:underline"
        >
          View Grades →
        </router-link>
      </template>

      <div v-if="loading" class="p-8 text-center">
        <span
          class="inline-block h-6 w-6 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"
        ></span>
        <p class="mt-3 text-xs font-bold text-[#6B7280]">Loading submissions...</p>
      </div>

      <div
        v-else-if="submissions.length === 0"
        class="rounded-2xl border border-dashed border-[#E7DCC3] bg-[#FAFAF7] p-8 text-center"
      >
        <p class="text-sm font-bold text-[#1F2937]">No submissions yet.</p>
        <p class="mt-1 text-xs text-[#6B7280]">
          Your submitted activities and grades will appear here.
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
              <th class="pb-4 text-center">Grade</th>
              <th class="pb-4 text-right">Status</th>
            </tr>
          </thead>

          <tbody class="divide-y divide-[#E7DCC3]/70">
            <tr
              v-for="submission in recentSubmissions"
              :key="submission.id"
              class="transition hover:bg-[#FAFAF7]"
            >
              <td class="py-4">
                <p class="font-black text-[#1F2937]">
                  {{ submission.subjectCode || 'Subject' }}
                </p>
                <p class="mt-0.5 text-xs text-[#6B7280]">
                  {{ submission.subjectTitle || 'No title' }}
                </p>
              </td>

              <td class="py-4">
                <p class="font-bold text-[#1F2937]">
                  {{ submission.activityTitle || submission.title || 'Activity' }}
                </p>

                <a
                  v-if="submission.fileUrl"
                  :href="submission.fileUrl"
                  target="_blank"
                  class="mt-1 inline-block text-xs font-semibold text-[#800000] hover:underline"
                >
                  View attachment
                </a>

                <p v-else class="mt-1 text-xs text-[#6B7280]">
                  Text submission
                </p>
              </td>

              <td class="py-4 text-center text-base font-black text-[#800000]">
                {{ submission.grade !== null && submission.grade !== undefined ? submission.grade : '—' }}
              </td>

              <td class="py-4 text-right">
                <span
                  :class="getStatusClass(submission.status)"
                  class="rounded-full border px-3 py-1 text-[11px] font-bold uppercase tracking-wider"
                >
                  {{ submission.status || 'submitted' }}
                </span>
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
  BarChart3Icon,
  BookOpenIcon,
  CheckCircle2Icon,
  CompassIcon,
  FileTextIcon,
} from 'lucide-vue-next'

const user = JSON.parse(localStorage.getItem('user') || '{}')

const loading = ref(true)
const error = ref('')

const subjects = ref([])
const pendingActivities = ref([])
const submissions = ref([])

const totalSubjects = computed(() => subjects.value.length)
const totalSubmitted = computed(() => submissions.value.length)
const totalPending = computed(() => pendingActivities.value.length)

const gradedSubmissions = computed(() => {
  return submissions.value.filter((submission) => submission.status === 'graded')
})

const runningAverage = computed(() => {
  if (gradedSubmissions.value.length === 0) return 0

  const validGrades = gradedSubmissions.value
    .map((submission) => Number(submission.grade))
    .filter((grade) => !Number.isNaN(grade))

  if (validGrades.length === 0) return 0

  const sum = validGrades.reduce((acc, grade) => acc + grade, 0)
  return Math.round(sum / validGrades.length)
})

const recentSubmissions = computed(() => {
  return submissions.value.slice(0, 5)
})

async function fetchStudentDashboard() {
  if (!user.uid) {
    error.value = 'No logged-in student found. Please log in again.'
    loading.value = false
    return
  }

  loading.value = true
  error.value = ''

  try {
    const enrollmentQuery = query(
      collection(db, 'enrollments'),
      where('studentId', '==', user.uid)
    )

    const enrollmentSnapshot = await getDocs(enrollmentQuery)

    subjects.value = enrollmentSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))

    const enrolledSubjectIds = subjects.value
      .map((subject) => subject.subjectId)
      .filter(Boolean)

    const submissionsQuery = query(
      collection(db, 'submissions'),
      where('studentId', '==', user.uid)
    )

    const submissionsSnapshot = await getDocs(submissionsQuery)

    submissions.value = submissionsSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))

    const submittedActivityIds = submissions.value
      .map((submission) => submission.activityId)
      .filter(Boolean)

    if (enrolledSubjectIds.length === 0) {
      pendingActivities.value = []
      return
    }

    const activitiesSnapshot = await getDocs(collection(db, 'activities'))

    const allActivities = activitiesSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))

    pendingActivities.value = allActivities
      .filter((activity) => {
        return (
          enrolledSubjectIds.includes(activity.subjectId) &&
          !submittedActivityIds.includes(activity.id)
        )
      })
      .slice(0, 5)
  } catch (err) {
    console.error('Failed to load student dashboard:', err)
    error.value = 'Unable to load your dashboard data. Please try again.'
  } finally {
    loading.value = false
  }
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

onMounted(fetchStudentDashboard)
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