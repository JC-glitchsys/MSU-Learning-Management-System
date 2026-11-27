<template>
  <div class="space-y-6 animate-fade-in">
    <div class="space-y-1">
      <h1 class="text-2xl font-semibold tracking-tight text-[#202124]">My Handled Subjects</h1>
      <p class="text-sm text-[#667085]">Access your assigned classroom streams and operations panels.</p>
    </div>

    <SkeletonLoader v-if="loading" variant="cards" card />

    <div v-else-if="error" class="rounded-lg border border-[#E7E9EE] bg-white p-8 text-center text-sm font-medium text-[#D93025]">
      {{ error }}
    </div>

    <div v-else-if="assignedSubjects.length === 0" class="rounded-lg border border-dashed border-[#DADCE0] bg-white p-8 text-center text-[#5F6368]">
      <p class="text-sm font-semibold text-[#202124]">No assigned subjects found.</p>
      <p class="mt-1 text-sm">Please contact the System Admin to allocate your curriculum sheets.</p>
    </div>

    <div v-else class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
      <div v-for="subj in assignedSubjects" :key="subj.id" class="group flex flex-col justify-between overflow-hidden rounded-lg border border-[#E7E9EE] bg-white transition-colors duration-200 hover:border-[#DADCE0]">
        
        <div class="subject-card-banner relative h-40 overflow-hidden p-5 text-[#800000]" :class="`subject-card-banner--${getSubjectArtworkType(subj)}`">
          <StudyToolsArtwork :subject="subj" />
          <div class="relative z-10 max-w-[58%]">
            <p class="truncate text-sm font-medium text-[#5C0000]">{{ subj.code }}</p>
            <h3 class="mt-1 truncate text-xl font-medium tracking-tight text-[#800000]">{{ subj.title }}</h3>
            <p class="mt-1 truncate text-xs text-[#5C0000]">{{ subj.program || 'General Program' }}<span v-if="subj.section"> · {{ subj.section }}</span></p>
          </div>
        </div>

        <div class="flex flex-1 flex-col justify-between space-y-4 bg-white p-4">
          <div class="grid grid-cols-3 gap-2 text-center">
            <router-link to="/instructor/upload-module" class="rounded-md border border-[#E7E9EE] bg-white px-2 py-2 text-xs font-medium text-[#800000] transition hover:bg-[#FDF0F0]">Modules</router-link>
            <router-link to="/instructor/create-activity" class="rounded-md border border-[#E7E9EE] bg-white px-2 py-2 text-xs font-medium text-[#800000] transition hover:bg-[#FDF0F0]">Activity</router-link>
            <router-link to="/instructor/submissions" class="rounded-md border border-[#E7E9EE] bg-white px-2 py-2 text-xs font-medium text-[#800000] transition hover:bg-[#FDF0F0]">Review</router-link>
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
import { collection, query, where, getDocs } from 'firebase/firestore'
import { db } from '../../firebase/config.js'

const assignedSubjects = ref([])
const loading = ref(true)
const error = ref('')

const user = JSON.parse(localStorage.getItem('user') || '{}')

const fetchAssignedStreams = async () => {
  if (!user.uid) {
    error.value = 'Identity validation verification mapping failed.'
    loading.value = false
    return
  }
  try {
    const q = query(collection(db, 'subjects'), where('instructorId', '==', user.uid))
    const snap = await getDocs(q)
    assignedSubjects.value = snap.docs.map(d => ({ id: d.id, ...d.data() })).filter((item) => item.archived !== true)
  } catch (err) {
    error.value = 'Security isolation failure fetching teacher tracks.'
  } finally {
    loading.value = false
  }
}

onMounted(fetchAssignedStreams)
</script>
