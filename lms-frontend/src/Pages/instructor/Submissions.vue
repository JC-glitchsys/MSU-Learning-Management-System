<template>
  <div class="space-y-6 animate-fade-in">
    <!-- Header -->
    <section
      class="rounded-[28px] border border-[#E7DCC3] bg-gradient-to-br from-white via-white to-[#FFF8E1] p-6 shadow-sm"
    >
      <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
        <div>
          <p class="text-xs font-bold uppercase tracking-[0.22em] text-[#D4AF37]">
            Instructor Queue
          </p>
          <h1 class="mt-2 text-2xl font-black tracking-tight text-[#800000] md:text-3xl">
            Student Submissions
          </h1>
          <p class="mt-1 max-w-2xl text-sm font-medium text-[#6B7280]">
            Review submitted activities, check their status, and grade student work.
          </p>
        </div>

        <div
          class="inline-flex w-fit rounded-full border border-[#E7DCC3] bg-white px-4 py-2 text-xs font-bold text-[#800000] shadow-sm"
        >
          {{ submissions.length }} submission{{ submissions.length === 1 ? '' : 's' }}
        </div>
      </div>
    </section>

    <!-- Main Card -->
    <section class="overflow-hidden rounded-[28px] border border-[#E7DCC3] bg-white shadow-sm">
      <!-- Loading -->
      <div v-if="loading" class="p-12 text-center">
        <span
          class="inline-block h-7 w-7 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"
        ></span>
        <p class="mt-3 text-sm font-bold text-[#6B7280]">Loading submissions...</p>
      </div>

      <!-- Empty -->
      <div v-else-if="submissions.length === 0" class="p-12 text-center">
        <div
          class="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-[#FFF8E1] text-[#800000]"
        >
          <InboxIcon class="h-7 w-7" />
        </div>
        <h2 class="mt-4 text-lg font-black text-[#1F2937]">
          No submissions yet
        </h2>
        <p class="mt-1 text-sm text-[#6B7280]">
          Student submissions for your activities will appear here.
        </p>
      </div>

      <!-- List -->
      <div v-else class="divide-y divide-[#E7DCC3]/70">
        <!-- Header Row desktop -->
        <div
          class="hidden grid-cols-12 gap-4 bg-[#FAFAF7] px-6 py-4 text-xs font-black uppercase tracking-wider text-[#6B7280] lg:grid"
        >
          <div class="col-span-3">Student</div>
          <div class="col-span-4">Activity</div>
          <div class="col-span-2 text-center">Status</div>
          <div class="col-span-3 text-right">Action</div>
        </div>

        <div
          v-for="sub in submissions"
          :key="sub.id"
          class="grid grid-cols-1 gap-4 px-6 py-5 transition hover:bg-[#FAFAF7] lg:grid-cols-12 lg:items-center"
        >
          <!-- Student -->
          <div class="min-w-0 lg:col-span-3">
            <div class="flex items-center gap-3">
              <div
                class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[#800000] to-[#5A0000] text-xs font-black text-white ring-2 ring-[#D4AF37]/40"
              >
                {{ getInitials(sub.studentName) }}
              </div>

              <div class="min-w-0">
                <p class="truncate text-sm font-black text-[#1F2937]">
                  {{ sub.studentName || 'Student' }}
                </p>
                <p class="mt-0.5 truncate text-xs font-medium text-[#6B7280]">
                  {{ sub.studentEmail || 'No email' }}
                </p>
              </div>
            </div>
          </div>

          <!-- Activity -->
          <div class="min-w-0 lg:col-span-4">
            <span
              class="mb-1 inline-flex rounded-full border border-[#E7DCC3] bg-[#FFF8E1] px-2.5 py-0.5 text-[10px] font-black uppercase tracking-wider text-[#800000]"
            >
              {{ sub.subjectCode || 'Subject' }}
            </span>

            <p class="truncate text-sm font-black text-[#1F2937]">
              {{ sub.activityTitle || 'Course Activity' }}
            </p>

            <p class="mt-0.5 text-xs text-[#6B7280]">
              Submitted: {{ formatDate(sub.submittedAt) }}
            </p>
          </div>

          <!-- Status -->
          <div class="lg:col-span-2 lg:text-center">
            <span
              :class="getStatusClass(sub.status)"
              class="inline-flex rounded-full border px-3 py-1 text-[10px] font-black uppercase tracking-wider"
            >
              {{ sub.status === 'graded' ? `Graded: ${sub.grade ?? '—'}` : 'Pending' }}
            </span>
          </div>

          <!-- Action -->
          <div class="lg:col-span-3 lg:text-right">
            <button
              @click="routeToGradeDesk(sub.id)"
              class="inline-flex items-center justify-center gap-2 rounded-full border border-[#E7DCC3] bg-white px-4 py-2 text-xs font-black text-[#800000] shadow-sm transition hover:bg-[#800000] hover:text-white"
            >
              <ClipboardCheckIcon class="h-4 w-4" />
              {{ sub.status === 'graded' ? 'Modify Grade' : 'Grade Work' }}
            </button>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { collection, getDocs, query, where } from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import { ClipboardCheckIcon, InboxIcon } from 'lucide-vue-next'

const router = useRouter()
const user = JSON.parse(localStorage.getItem('user') || '{}')

const loading = ref(true)
const submissions = ref([])

async function fetchInstructorReviewQueue() {
  loading.value = true

  try {
    const activitiesSnapshot = await getDocs(
      query(collection(db, 'activities'), where('createdBy', '==', user.uid))
    )

    const instructorActivityMap = activitiesSnapshot.docs.reduce((acc, document) => {
      const data = document.data()

      acc[document.id] = {
        title: data.title || 'Course Activity',
        subjectCode: data.subjectCode || '',
        subjectTitle: data.subjectTitle || '',
      }

      return acc
    }, {})

    const activityIds = Object.keys(instructorActivityMap)

    if (activityIds.length === 0) {
      submissions.value = []
      return
    }

    const submissionsSnapshot = await getDocs(collection(db, 'submissions'))

    submissions.value = submissionsSnapshot.docs
      .map((document) => {
        const data = document.data()
        const activityInfo = instructorActivityMap[data.activityId] || {}

        return {
          id: document.id,
          ...data,
          activityTitle: data.activityTitle || activityInfo.title || 'Course Activity',
          subjectCode: data.subjectCode || activityInfo.subjectCode || '',
          subjectTitle: data.subjectTitle || activityInfo.subjectTitle || '',
        }
      })
      .filter((submission) => activityIds.includes(submission.activityId))
      .sort((a, b) => {
        const aTime = a.submittedAt?.seconds || 0
        const bTime = b.submittedAt?.seconds || 0
        return bTime - aTime
      })
  } catch (err) {
    console.error('Fetch submissions error:', err)
  } finally {
    loading.value = false
  }
}

function routeToGradeDesk(submissionId) {
  router.push({
    path: '/instructor/grade-submission',
    query: { id: submissionId },
  })
}

function getInitials(name) {
  if (!name) return 'ST'

  return name
    .split(' ')
    .filter(Boolean)
    .map((word) => word.charAt(0))
    .join('')
    .toUpperCase()
    .slice(0, 2)
}

function formatDate(value) {
  if (!value) return 'No date'

  if (typeof value === 'string') return value

  if (value?.toDate) {
    return value.toDate().toLocaleDateString()
  }

  if (value?.seconds) {
    return new Date(value.seconds * 1000).toLocaleDateString()
  }

  return 'No date'
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

onMounted(fetchInstructorReviewQueue)
</script>

<style scoped>
.animate-fade-in {
  animation: fadeIn 0.22s ease-out forwards;
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