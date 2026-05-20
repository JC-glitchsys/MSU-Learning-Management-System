<template>
  <div class="space-y-6 animate-fade-in">
    <!-- Header -->
    <section
      class="overflow-hidden rounded-[28px] border border-[#E7DCC3] bg-white shadow-sm"
    >
      <div
        class="relative bg-gradient-to-r from-[#800000] via-[#8F1111] to-[#D4AF37] p-6 text-white md:p-7"
      >
        <div class="absolute -right-10 -top-10 h-36 w-36 rounded-full bg-white/10"></div>
        <div class="absolute -bottom-12 left-10 h-32 w-32 rounded-full bg-black/10"></div>

        <div class="relative flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <button
              @click="backToQueue"
              class="mb-4 inline-flex items-center gap-2 rounded-full bg-white/10 px-4 py-2 text-xs font-bold text-white ring-1 ring-white/20 transition hover:bg-white/20"
            >
              <ArrowLeftIcon class="h-4 w-4" />
              Back to Submissions
            </button>

            <p class="text-xs font-bold uppercase tracking-[0.24em] text-white/70">
              Grade Submission
            </p>

            <h1 class="mt-2 text-2xl font-black tracking-tight md:text-3xl">
              Review Student Work
            </h1>

            <p class="mt-1 max-w-2xl text-sm font-medium text-white/80">
              Check the submitted answer, review attachments, then provide grade and feedback.
            </p>
          </div>

          <div
            class="inline-flex w-fit items-center gap-2 rounded-full border border-white/20 bg-white/15 px-4 py-2 text-xs font-bold text-white backdrop-blur"
          >
            <ClipboardCheckIcon class="h-4 w-4" />
            Instructor Evaluation
          </div>
        </div>
      </div>
    </section>

    <!-- Loading -->
    <section
      v-if="loading"
      class="rounded-[28px] border border-[#E7DCC3] bg-white p-12 text-center shadow-sm"
    >
      <span
        class="inline-block h-7 w-7 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"
      ></span>
      <p class="mt-3 text-sm font-bold text-[#6B7280]">
        Loading submission...
      </p>
    </section>

    <!-- Error / Empty -->
    <section
      v-else-if="error || !submission"
      class="rounded-[28px] border border-red-200 bg-red-50 p-8 text-center shadow-sm"
    >
      <AlertCircleIcon class="mx-auto h-10 w-10 text-red-600" />
      <h2 class="mt-3 text-lg font-black text-red-700">
        Submission not found
      </h2>
      <p class="mt-1 text-sm font-medium text-red-600">
        {{ error || 'The selected submission record could not be loaded.' }}
      </p>

      <button
        @click="backToQueue"
        class="mt-5 rounded-full bg-[#800000] px-5 py-2.5 text-xs font-bold text-white transition hover:bg-[#5A0000]"
      >
        Return to Submissions
      </button>
    </section>

    <!-- Main Content -->
    <section v-else class="grid grid-cols-1 gap-6 xl:grid-cols-12">
      <!-- Submission Details -->
      <div class="space-y-6 xl:col-span-7">
        <!-- Student + Activity Summary -->
        <div
          class="rounded-[28px] border border-[#E7DCC3] bg-gradient-to-br from-white via-white to-[#FFF8E1] p-6 shadow-sm"
        >
          <div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
            <div>
              <span
                class="inline-flex rounded-full border border-[#E7DCC3] bg-[#FFF8E1] px-3 py-1 text-[10px] font-black uppercase tracking-wider text-[#800000]"
              >
                {{ submission.subjectCode || 'Subject' }}
              </span>

              <h2 class="mt-3 text-xl font-black text-[#1F2937]">
                {{ submission.activityTitle || submission.title || 'Submitted Activity' }}
              </h2>

              <p class="mt-1 text-sm font-medium text-[#6B7280]">
                {{ submission.subjectTitle || 'No subject title' }}
              </p>
            </div>

            <span
              :class="getStatusClass(submission.status)"
              class="inline-flex w-fit rounded-full border px-3 py-1 text-[10px] font-black uppercase tracking-wider"
            >
              {{ submission.status || 'submitted' }}
            </span>
          </div>

          <div class="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div class="rounded-2xl border border-[#E7DCC3] bg-white p-4">
              <p class="text-[10px] font-bold uppercase tracking-wider text-[#6B7280]">
                Student
              </p>
              <p class="mt-1 truncate text-sm font-black text-[#1F2937]">
                {{ submission.studentName || 'Student' }}
              </p>
            </div>

            <div class="rounded-2xl border border-[#E7DCC3] bg-white p-4">
              <p class="text-[10px] font-bold uppercase tracking-wider text-[#6B7280]">
                Submitted
              </p>
              <p class="mt-1 text-sm font-black text-[#1F2937]">
                {{ formatDate(submission.submittedAt) }}
              </p>
            </div>

            <div class="rounded-2xl border border-[#E7DCC3] bg-white p-4">
              <p class="text-[10px] font-bold uppercase tracking-wider text-[#6B7280]">
                Current Grade
              </p>
              <p class="mt-1 text-sm font-black text-[#800000]">
                {{ submission.grade !== null && submission.grade !== undefined ? submission.grade : 'Not graded' }}
              </p>
            </div>
          </div>
        </div>

        <!-- Answer -->
        <div class="rounded-[28px] border border-[#E7DCC3] bg-white p-6 shadow-sm">
          <div class="mb-4 flex items-center gap-3">
            <div
              class="flex h-10 w-10 items-center justify-center rounded-xl bg-[#FFF8E1] text-[#800000] ring-1 ring-[#E7DCC3]"
            >
              <FileTextIcon class="h-5 w-5" />
            </div>

            <div>
              <h3 class="text-base font-black text-[#1F2937]">
                Student Answer
              </h3>
              <p class="text-xs text-[#6B7280]">
                Review the submitted text response.
              </p>
            </div>
          </div>

          <div
            class="min-h-[180px] rounded-2xl border border-[#E7DCC3] bg-[#FAFAF7] p-5 text-sm leading-relaxed text-[#1F2937] whitespace-pre-wrap"
          >
            {{ submission.answerText || 'No written answer was submitted.' }}
          </div>
        </div>

        <!-- Attachment -->
        <div
          v-if="submission.fileUrl"
          class="rounded-[28px] border border-[#E7DCC3] bg-white p-6 shadow-sm"
        >
          <div class="mb-4 flex items-center gap-3">
            <div
              class="flex h-10 w-10 items-center justify-center rounded-xl bg-[#FFF8E1] text-[#800000] ring-1 ring-[#E7DCC3]"
            >
              <PaperclipIcon class="h-5 w-5" />
            </div>

            <div>
              <h3 class="text-base font-black text-[#1F2937]">
                Attachment
              </h3>
              <p class="text-xs text-[#6B7280]">
                Open the submitted file or external link.
              </p>
            </div>
          </div>

          <div
            class="flex flex-col gap-3 rounded-2xl border border-[#E7DCC3] bg-gradient-to-r from-white to-[#FFF8E1] p-4 sm:flex-row sm:items-center sm:justify-between"
          >
            <p class="min-w-0 truncate text-xs font-bold text-[#800000]">
              {{ submission.fileUrl }}
            </p>

            <a
              :href="submission.fileUrl"
              target="_blank"
              class="inline-flex shrink-0 items-center justify-center gap-2 rounded-full bg-[#800000] px-4 py-2 text-xs font-bold text-white transition hover:bg-[#5A0000]"
            >
              Open File
              <ExternalLinkIcon class="h-3.5 w-3.5" />
            </a>
          </div>
        </div>
      </div>

      <!-- Grading Form -->
      <aside class="xl:col-span-5">
        <div
          class="sticky top-28 rounded-[28px] border border-[#E7DCC3] bg-white p-6 shadow-sm"
        >
          <!-- Student Card -->
          <div
            class="mb-6 rounded-2xl border border-[#E7DCC3] bg-gradient-to-br from-white to-[#FFF8E1] p-4"
          >
            <div class="flex items-center gap-3">
              <div
                class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[#800000] to-[#5A0000] text-sm font-black text-white ring-2 ring-[#D4AF37]/40"
              >
                {{ getInitials(submission.studentName) }}
              </div>

              <div class="min-w-0">
                <p class="truncate text-sm font-black text-[#1F2937]">
                  {{ submission.studentName || 'Student' }}
                </p>
                <p class="truncate text-xs text-[#6B7280]">
                  {{ submission.studentEmail || 'No email available' }}
                </p>
              </div>
            </div>
          </div>

          <form @submit.prevent="saveGrade" class="space-y-5">
            <div>
              <label
                class="mb-2 block text-[11px] font-black uppercase tracking-wider text-[#1F2937]"
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
                  class="w-28 rounded-[14px] border border-[#E7DCC3] bg-white px-4 py-3 text-center text-lg font-black text-[#800000] outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
                />

                <span class="text-sm font-bold text-[#6B7280]">
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
                class="mb-2 block text-[11px] font-black uppercase tracking-wider text-[#1F2937]"
              >
                Feedback
              </label>

              <textarea
                v-model="feedbackText"
                rows="6"
                placeholder="Write feedback for the student..."
                class="w-full resize-none rounded-[16px] border border-[#E7DCC3] bg-white px-4 py-3 text-sm leading-relaxed text-[#1F2937] outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
              ></textarea>
            </div>

            <button
              type="submit"
              :disabled="committing"
              class="inline-flex w-full items-center justify-center gap-2 rounded-full bg-[#800000] px-6 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-[#5A0000] disabled:cursor-not-allowed disabled:opacity-60"
            >
              <SaveIcon class="h-4 w-4" />
              {{ committing ? 'Saving Grade...' : 'Save Grade and Feedback' }}
            </button>

            <button
              type="button"
              @click="backToQueue"
              class="w-full rounded-full border border-[#E7DCC3] bg-white px-6 py-3 text-sm font-bold text-[#800000] transition hover:bg-[#FFF8E1]"
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
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  doc,
  getDoc,
  serverTimestamp,
  updateDoc,
} from 'firebase/firestore'
import { db } from '../../firebase/config.js'
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

    alert('Grade and feedback saved successfully.')
    backToQueue()
  } catch (err) {
    console.error('Save grade error:', err)
    error.value = 'Unable to save grade. Please try again.'
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
    return 'border-green-200 bg-green-50 text-green-700'
  }

  if (status === 'late') {
    return 'border-red-200 bg-red-50 text-red-700'
  }

  return 'border-amber-200 bg-amber-50 text-amber-700'
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