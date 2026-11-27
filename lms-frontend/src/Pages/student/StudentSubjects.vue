<template>
  <div class="space-y-6 animate-fade-in">
    <div class="space-y-1">
      <h1 class="text-2xl font-semibold tracking-tight text-[#202124]">My Enrolled Classes</h1>
      <p class="text-sm text-[#667085]">Select an active class card to open the classroom workspace stream.</p>
    </div>

    <SkeletonLoader v-if="loading" variant="cards" card />

    <div v-else-if="error" class="rounded-lg border border-[#E7E9EE] bg-white p-8 text-center text-sm font-medium text-[#D93025]">
      {{ error }}
    </div>

    <div v-else-if="enrolledSubjects.length === 0" class="rounded-lg border border-dashed border-[#DADCE0] bg-white p-8 text-center text-[#5F6368]">
      <p class="text-4xl">📚</p>
      <p class="mt-2 text-sm font-semibold text-[#202124]">You are not enrolled in any subjects yet.</p>
      <p class="mt-1 text-sm">Please coordinate with your system registrar or program adviser.</p>
    </div>

    <div v-else class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
      <div 
        v-for="sub in enrolledSubjects" 
        :key="sub.id"
        @click="openSubjectStream(sub.subjectId)"
        class="group flex cursor-pointer flex-col justify-between overflow-hidden rounded-lg border border-[#E7E9EE] bg-white transition-colors duration-200 hover:border-[#DADCE0]"
      >
        <div class="subject-card-banner relative h-40 shrink-0 overflow-hidden p-5 text-[#800000]" :class="`subject-card-banner--${getSubjectArtworkType(sub)}`">
          <StudyToolsArtwork :subject="sub" />
          <div class="relative z-10 max-w-[58%]">
            <p class="truncate text-sm font-medium text-[#5C0000]">{{ sub.subjectCode }}</p>
            <h3 class="mt-1 truncate text-xl font-medium tracking-tight text-[#800000]">{{ sub.subjectTitle }}</h3>
          </div>
        </div>

        <div class="flex flex-1 flex-col justify-between space-y-4 bg-white p-4">
          <div class="space-y-1">
            <p class="truncate text-sm font-medium text-[#202124]">{{ sub.instructorName || 'Unassigned Faculty' }}</p>
            <p v-if="sub.section" class="text-sm text-[#667085]">{{ sub.section }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import SkeletonLoader from '@/components/common/SkeletonLoader.vue'
import StudyToolsArtwork from '@/components/common/StudyToolsArtwork.vue'
import { getSubjectArtworkType } from '@/utils/subjectArtwork.js'
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { collection, query, where, getDocs } from 'firebase/firestore'
import { db } from '../../firebase/config.js'

const router = useRouter()
const enrolledSubjects = ref([])
const loading = ref(true)
const error = ref('')

const user = JSON.parse(localStorage.getItem('user') || '{}')

const fetchStudentEnrollments = async () => {
  if (!user.uid) {
    error.value = 'Identity mapping missing. Please log in again.'
    loading.value = false
    return
  }
  loading.value = true
  try {
    const q = query(collection(db, 'enrollments'), where('studentId', '==', user.uid))
    const snap = await getDocs(q)
    const subjectSnap = await getDocs(collection(db, 'subjects'))
    const subjectById = new Map(subjectSnap.docs.map((document) => [
      document.id,
      { id: document.id, ...document.data() },
    ]))
    const activeSubjectIds = new Set(subjectSnap.docs
      .filter((subject) => subject.data().archived !== true)
      .map((subject) => subject.id))
    enrolledSubjects.value = snap.docs.map((document) => {
      const enrollment = { id: document.id, ...document.data() }
      const subject = subjectById.get(enrollment.subjectId) || {}

      return {
        ...subject,
        ...enrollment,
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
  } catch (err) {
    console.error(err)
    error.value = 'Failed to fetch your academic enrollment collection.'
  } finally {
    loading.value = false
  }
}

const openSubjectStream = (subjectId) => {
  router.push(`/student/subjects/${subjectId}`)
}

onMounted(fetchStudentEnrollments)
</script>

<style scoped>
.animate-fade-in { animation: fadeIn 0.2s ease-out forwards; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
</style>
