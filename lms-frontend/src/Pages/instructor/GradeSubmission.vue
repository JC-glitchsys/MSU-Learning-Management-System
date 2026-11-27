<template>
  <div class="space-y-6 animate-fade-in">
    <!-- Header -->
    <section
      class="overflow-hidden rounded-lg border border-[#E7E9EE] bg-white"
    >
      <div
        class="relative bg-[#F8F9FA] p-6 text-[#202124] md:p-7"
      >
        <div class="relative flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <button
              @click="backToQueue"
              class="mb-4 inline-flex items-center gap-2 rounded-md border border-[#E7E9EE] bg-white px-3 py-2 text-sm font-medium text-[#5F6368] transition hover:bg-[#F3F4F6]"
            >
              <ArrowLeftIcon class="h-4 w-4" />
              Back to Submissions
            </button>

            <h1 class="mt-2 text-2xl font-semibold tracking-tight">
              Review Student Work
            </h1>

            <p class="mt-1 max-w-2xl text-sm text-[#667085]">
              Check the submitted answer, review attachments, then provide grade and feedback.
            </p>
          </div>

          <div
            class="inline-flex w-fit items-center gap-2 rounded-md border border-[#E7E9EE] bg-white px-3 py-2 text-sm font-medium text-[#800000]"
          >
            <ClipboardCheckIcon class="h-4 w-4" />
            Instructor Evaluation
          </div>
        </div>
      </div>
    </section>

    <!-- Loading -->
    <SkeletonLoader v-if="loading" variant="details" card />

    <!-- Error / Empty -->
    <section
      v-else-if="error || !submission"
      class="rounded-lg border border-[#E7E9EE] bg-white p-8 text-center"
    >
      <AlertCircleIcon class="mx-auto h-10 w-10 text-[#D93025]" />
      <h2 class="mt-3 text-lg font-black text-[#D93025]">
        Submission not found
      </h2>
      <p class="mt-1 text-sm font-medium text-[#D93025]">
        {{ error || 'The selected submission record could not be loaded.' }}
      </p>

      <button
        @click="backToQueue"
        class="mt-5 rounded-md bg-[#800000] px-4 py-2.5 text-sm font-medium text-white transition hover:bg-[#5C0000]"
      >
        Return to Submissions
      </button>
    </section>

    <!-- Main Content -->
    <section v-else class="grid grid-cols-1 gap-6 xl:grid-cols-12">
      <!-- Submission Details -->
      <div class="space-y-6 xl:col-span-8">
        <!-- Student + Activity Summary -->
        <div
          class="rounded-lg border border-[#E7E9EE] bg-white p-5"
        >
          <div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
            <div>
              <span
                class="inline-flex rounded-md border border-[#E7E9EE] bg-[#F8F9FA] px-2.5 py-1 text-xs font-medium text-[#800000]"
              >
                {{ submission.subjectCode || 'Subject' }}
              </span>

              <h2 class="mt-3 text-lg font-semibold text-[#202124]">
                {{ submission.activityTitle || submission.title || 'Submitted Activity' }}
              </h2>

              <p class="mt-1 text-sm text-[#667085]">
                {{ submission.subjectTitle || 'No subject title' }}
              </p>
            </div>

            <span
              :class="getStatusClass(submission.status)"
              class="inline-flex w-fit rounded-md border px-2.5 py-1 text-xs font-medium"
            >
              {{ submission.status || 'submitted' }}
            </span>
          </div>

          <div class="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div class="rounded-md border border-[#E7E9EE] bg-white p-3">
              <p class="text-xs font-medium text-[#667085]">
                Student
              </p>
              <p class="mt-1 truncate text-sm font-medium text-[#202124]">
                {{ submission.studentName || 'Student' }}
              </p>
            </div>

            <div class="rounded-md border border-[#E7E9EE] bg-white p-3">
              <p class="text-xs font-medium text-[#667085]">
                Submitted
              </p>
              <p class="mt-1 text-sm font-medium text-[#202124]">
                {{ formatDate(submission.submittedAt) }}
              </p>
            </div>

            <div class="rounded-md border border-[#E7E9EE] bg-white p-3">
              <p class="text-xs font-medium text-[#667085]">
                Current Grade
              </p>
              <p class="mt-1 text-sm font-medium text-[#800000]">
                {{ submission.grade !== null && submission.grade !== undefined ? submission.grade : 'Not graded' }}
              </p>
            </div>
          </div>
        </div>

        <!-- Answer -->
        <div class="rounded-lg border border-[#E7E9EE] bg-white p-5">
          <div class="mb-4 flex items-center gap-3">
            <div
              class="flex h-9 w-9 items-center justify-center rounded-md border border-[#E7E9EE] bg-[#FDF0F0] text-[#800000]"
            >
              <FileTextIcon class="h-5 w-5" />
            </div>

            <div>
              <h3 class="text-base font-semibold text-[#202124]">
                Student Answer
              </h3>
              <p class="text-xs text-[#5F6368]">
                Review the submitted text response.
              </p>
            </div>
          </div>

          <div
            class="min-h-[180px] whitespace-pre-wrap rounded-md border border-[#E7E9EE] bg-[#F8F9FA] p-4 text-sm leading-relaxed text-[#202124]"
          >
            {{ submission.answerText || 'No written answer was submitted.' }}
          </div>
        </div>

        <!-- Attachment -->
        <div
          v-if="submission.fileUrl"
          class="rounded-lg border border-[#E7E9EE] bg-white p-5"
        >
          <div class="mb-4 flex items-center gap-3">
            <div
              class="flex h-9 w-9 items-center justify-center rounded-md border border-[#E7E9EE] bg-[#FDF0F0] text-[#800000]"
            >
              <PaperclipIcon class="h-5 w-5" />
            </div>

            <div>
              <h3 class="text-base font-semibold text-[#202124]">
                Attachment
              </h3>
              <p class="text-xs text-[#5F6368]">
                Open the submitted file or external link.
              </p>
            </div>
          </div>

          <div
            class="flex flex-col gap-3 rounded-md border border-[#E7E9EE] bg-[#F8F9FA] p-4 sm:flex-row sm:items-center sm:justify-between"
          >
            <p class="min-w-0 truncate text-xs font-bold text-[#800000]">
              {{ submission.fileUrl }}
            </p>

            <a
              :href="submission.fileUrl"
              target="_blank"
              class="inline-flex shrink-0 items-center justify-center gap-2 rounded-md bg-[#800000] px-3 py-2 text-sm font-medium text-white transition hover:bg-[#5C0000]"
            >
              Open File
              <ExternalLinkIcon class="h-3.5 w-3.5" />
            </a>
          </div>
        </div>
      </div>

      <!-- Grading Form -->
      <aside class="xl:col-span-4">
        <div
          class="rounded-lg border border-[#E7E9EE] bg-white p-5"
        >
          <!-- Student Card -->
          <div
            class="mb-5 rounded-md border border-[#E7E9EE] bg-[#F8F9FA] p-4"
          >
            <div class="flex items-center gap-3">
              <div
                class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#800000] text-sm font-medium text-white"
              >
                {{ getInitials(submission.studentName) }}
              </div>

              <div class="min-w-0">
                <p class="truncate text-sm font-medium text-[#202124]">
                  {{ submission.studentName || 'Student' }}
                </p>
                <p class="truncate text-xs text-[#5F6368]">
                  {{ submission.studentEmail || 'No email available' }}
                </p>
              </div>
            </div>
          </div>

          <form @submit.prevent="saveGrade" class="space-y-5">
            <div>
              <label
                class="mb-2 block text-sm font-medium text-[#202124]"
              >
                Grade
              </label>

              <div class="flex items-center gap-3">
                <input
                  v-model="gradeScore"
                  required
                  type="number"
                  min="0"
                  :max="submission.points || undefined"
                  placeholder="Score"
                  class="w-28 rounded-md border border-[#DADCE0] bg-white px-3 py-2 text-center text-base font-medium text-[#800000] outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
                />

                <span class="text-sm text-[#667085]">
                  <template v-if="submission.points">
                    / {{ submission.points }} points
                  </template>
                  <template v-else>
                    points
                  </template>
                </span>
              </div>
            </div>

            <div>
              <label
                class="mb-2 block text-sm font-medium text-[#202124]"
              >
                Feedback
              </label>

              <textarea
                v-model="feedbackText"
                rows="6"
                placeholder="Write feedback for the student..."
                class="w-full resize-none rounded-md border border-[#DADCE0] bg-white px-3 py-2.5 text-sm leading-relaxed text-[#202124] outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              ></textarea>
            </div>

            <button
              type="submit"
              :disabled="committing"
              class="inline-flex h-10 w-full items-center justify-center gap-2 rounded-md bg-[#800000] px-4 text-sm font-medium text-white transition hover:bg-[#5C0000] disabled:cursor-not-allowed disabled:opacity-60"
            >
              <SaveIcon class="h-4 w-4" />
              {{ committing ? 'Saving Grade...' : 'Save Grade and Feedback' }}
            </button>

            <button
              type="button"
              @click="backToQueue"
              class="h-10 w-full rounded-md border border-[#E7E9EE] bg-white px-4 text-sm font-medium text-[#800000] transition hover:bg-[#FDF0F0]"
            >
              Cancel
            </button>
          </form>
        </div>
      </aside>
    </section>
  </div>
</template>

<script setup>
import SkeletonLoader from '@/components/common/SkeletonLoader.vue'
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  doc,
  getDoc,
  serverTimestamp,
  updateDoc,
} from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import { showResult } from '@/utils/resultMessage'
import {
  AlertCircleIcon,
  ArrowLeftIcon,
  ClipboardCheckIcon,
  ExternalLinkIcon,
  FileTextIcon,
  PaperclipIcon,
  SaveIcon,
} from 'lucide-vue-next'

const route = useRoute()
const router = useRouter()

const submissionId = route.query.id || route.params.id

const loading = ref(true)
const committing = ref(false)
const error = ref('')
const submission = ref(null)

const gradeScore = ref('')
const feedbackText = ref('')

async function fetchSubmission() {
  if (!submissionId) {
    error.value = 'Missing submission ID.'
    loading.value = false
    return
  }

  loading.value = true
  error.value = ''

  try {
    const snap = await getDoc(doc(db, 'submissions', submissionId))

    if (!snap.exists()) {
      error.value = 'Submission document does not exist.'
      submission.value = null
      return
    }

    submission.value = {
      id: snap.id,
      ...snap.data(),
    }

    gradeScore.value =
      submission.value.grade !== null && submission.value.grade !== undefined
        ? submission.value.grade
        : ''

    feedbackText.value = submission.value.feedback || ''
  } catch (err) {
    console.error('Fetch submission error:', err)
    error.value = 'Unable to load submission. Please try again.'
  } finally {
    loading.value = false
  }
}

async function saveGrade() {
  if (!submissionId) return

  committing.value = true
  error.value = ''

  try {
    await updateDoc(doc(db, 'submissions', submissionId), {
      grade: Number(gradeScore.value),
      feedback: feedbackText.value.trim(),
      status: 'graded',
      gradedAt: serverTimestamp(),
    })

    showResult('Grade Saved', 'The grade and feedback have been recorded.')
    backToQueue()
  } catch (err) {
    console.error('Save grade error:', err)
    error.value = 'Unable to save grade. Please try again.'
    showResult('Could Not Save Grade', 'Please try again.', 'error')
  } finally {
    committing.value = false
  }
}

function backToQueue() {
  router.push('/instructor/submissions')
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
    return 'border-[#DADCE0] bg-white text-[#188038]'
  }

  if (status === 'late') {
    return 'border-[#DADCE0] bg-white text-[#D93025]'
  }

  return 'border-[#DADCE0] bg-white text-[#D93025]'
}

onMounted(fetchSubmission)
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
