<template>
  <div class="space-y-8 animate-fade-in">
    <!-- Error -->
    <div
      v-if="error"
      class="rounded-[24px] border border-[#DADCE0] bg-white p-5 text-sm font-semibold text-[#D93025]"
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
            <p class="text-sm font-bold text-[#202124]">No enrolled subjects yet.</p>
            <p class="mt-1 text-xs text-[#5F6368]">
              Once the admin enrolls you in a subject, it will appear here.
            </p>
          </div>

          <div v-else class="grid grid-cols-1 gap-4">
            <router-link
              v-for="subject in subjects"
              :key="subject.id"
              :to="`/student/subjects/${subject.subjectId}`"
              class="group overflow-hidden rounded-[22px] border border-[#DADCE0] bg-white shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
            >
              <div class="subject-card-banner relative h-40 overflow-hidden p-5 text-[#800000]" :class="`subject-card-banner--${getSubjectArtworkType(subject)}`">
                <StudyToolsArtwork :subject="subject" />
                <div class="relative z-10 max-w-[58%]">
                    <p class="truncate text-sm font-medium text-[#5C0000]">
                      {{ subject.subjectCode || 'No Code' }}
                    </p>

                    <h2 class="mt-1 truncate text-lg font-medium text-[#800000]">
                      {{ subject.subjectTitle || 'Untitled Subject' }}
                    </h2>

                    <p class="mt-1 truncate text-xs text-[#5C0000]">
                      Instructor: {{ subject.instructorName || 'Not assigned' }}
                    </p>
                </div>
              </div>

              <div class="flex items-center justify-between p-4">
                <div>
                  <p class="text-xs text-[#5F6368]">
                    Enrollment Status
                  </p>
                  <p class="mt-1 text-sm font-medium text-[#202124]">
                    Active
                  </p>
                </div>
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
              class="text-xs font-bold uppercase tracking-wide text-[#800000] hover:text-[#5C0000] hover:underline"
            >
              Open Tasks →
            </router-link>
          </template>

          <SkeletonLoader v-if="loading" variant="rows" />

          <div
            v-else-if="pendingActivities.length === 0"
            class="rounded-2xl border border-dashed border-[#DADCE0] bg-[#F8F9FA] p-8 text-center"
          >
            <p class="text-sm font-bold text-[#202124]">No pending activities.</p>
            <p class="mt-1 text-xs text-[#5F6368]">
              You are all caught up for now.
            </p>
          </div>

          <div v-else class="space-y-3.5">
            <div
              v-for="activity in pendingActivities"
              :key="activity.id"
              class="rounded-2xl border border-[#DADCE0] bg-white p-4 transition hover:border-[#FDF0F0] hover:shadow-sm"
            >
              <div class="flex items-start gap-3">
                <div
                  class="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#DADCE0] bg-[#FDF0F0] text-[#800000]"
                >
                  <FileTextIcon class="h-4 w-4 stroke-[2]" />
                </div>

                <div class="min-w-0 flex-1">
                  <p class="truncate text-sm font-black text-[#202124]">
                    {{ activity.title || 'Untitled Activity' }}
                  </p>

                  <p class="mt-0.5 text-xs font-medium text-[#5F6368]">
                    {{ activity.subjectCode || 'Subject' }}
                    <span v-if="activity.points"> • {{ activity.points }} pts</span>
                  </p>

                  <p class="mt-2 line-clamp-2 text-xs text-[#5F6368]">
                    {{ activity.instructions || 'No instructions provided.' }}
                  </p>
                </div>
              </div>

              <div class="mt-4 flex items-center justify-between gap-3">
                <span
                  class="rounded-full border border-[#DADCE0] bg-white px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-[#D93025]"
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
          class="text-xs font-bold uppercase tracking-wide text-[#800000] hover:text-[#5C0000] hover:underline"
        >
          View Grades →
        </router-link>
      </template>

      <SkeletonLoader v-if="loading" variant="table" />

      <div
        v-else-if="submissions.length === 0"
        class="rounded-2xl border border-dashed border-[#DADCE0] bg-[#F8F9FA] p-8 text-center"
      >
        <p class="text-sm font-bold text-[#202124]">No submissions yet.</p>
        <p class="mt-1 text-xs text-[#5F6368]">
          Your submitted activities and grades will appear here.
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
              <th class="pb-4 text-center">Grade</th>
              <th class="pb-4 text-right">Status</th>
            </tr>
          </thead>

          <tbody class="divide-y divide-[#DADCE0]/70">
            <tr
              v-for="submission in recentSubmissions"
              :key="submission.id"
              class="transition hover:bg-[#F8F9FA]"
            >
              <td class="py-4">
                <p class="font-black text-[#202124]">
                  {{ submission.subjectCode || 'Subject' }}
                </p>
                <p class="mt-0.5 text-xs text-[#5F6368]">
                  {{ submission.subjectTitle || 'No title' }}
                </p>
              </td>

              <td class="py-4">
                <p class="font-bold text-[#202124]">
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

                <p v-else class="mt-1 text-xs text-[#5F6368]">
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
import SkeletonLoader from '@/components/common/SkeletonLoader.vue'
import StudyToolsArtwork from '@/components/common/StudyToolsArtwork.vue'
import { getSubjectArtworkType } from '@/utils/subjectArtwork.js'
import { computed, onMounted, ref } from 'vue'
import { collection, getDocs, query, where } from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import CardPanel from '@/components/common/CardPanel.vue'
import {
  FileTextIcon,
} from 'lucide-vue-next'

const user = JSON.parse(localStorage.getItem('user') || '{}')

const loading = ref(true)
const error = ref('')

const subjects = ref([])
const pendingActivities = ref([])
const submissions = ref([])

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
    const subjectSnapshot = await getDocs(collection(db, 'subjects'))
    const subjectById = new Map(subjectSnapshot.docs.map((document) => [
      document.id,
      { id: document.id, ...document.data() },
    ]))
    const activeSubjectIds = new Set(subjectSnapshot.docs
      .filter((subject) => subject.data().archived !== true)
      .map((subject) => subject.id))

    subjects.value = enrollmentSnapshot.docs.map((document) => {
      const enrollment = { id: document.id, ...document.data() }
      const subject = subjectById.get(enrollment.subjectId) || {}

      return {
        ...subject,
        ...enrollment,
        title: subject.title || enrollment.subjectTitle,
        code: subject.code || enrollment.subjectCode,
        subjectTitle: subject.title || enrollment.subjectTitle,
        subjectCode: subject.code || enrollment.subjectCode,
        description: subject.description,
        program: subject.program,
        category: subject.category,
        subjectCategory: subject.subjectCategory,
        subjectArea: subject.subjectArea,
        discipline: subject.discipline,
      }
    }).filter((item) => item.archived !== true && activeSubjectIds.has(item.subjectId))

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
    })).filter((activity) => activity.archived !== true)

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
    return 'border-[#DADCE0] bg-white text-[#188038]'
  }

  if (status === 'late') {
    return 'border-[#DADCE0] bg-white text-[#D93025]'
  }

  return 'border-[#DADCE0] bg-white text-[#D93025]'
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
