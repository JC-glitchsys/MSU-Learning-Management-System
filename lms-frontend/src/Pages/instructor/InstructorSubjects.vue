<template>
  <div class="space-y-8 animate-fade-in">
    <div>
      <h2 class="text-3xl md:text-4xl font-bold text-[#800000] tracking-tight">My Handled Subjects</h2>
      <p class="text-[#5F6368] mt-2 font-medium text-sm">Access your assigned classroom streams and operations panels.</p>
    </div>

    <SkeletonLoader v-if="loading" variant="cards" card />

    <div v-else-if="error" class="p-12 text-center bg-white rounded-[28px] border border-[#DADCE0] shadow-sm text-[#D93025] font-bold">
      {{ error }}
    </div>

    <div v-else-if="assignedSubjects.length === 0" class="p-12 text-center bg-white rounded-[28px] border border-[#DADCE0] shadow-sm text-[#5F6368]">
      <p class="text-sm font-bold mt-2">No assigned subjects found.</p>
      <p class="text-xs mt-0.5">Please contact the System Admin to allocate your curriculum sheets.</p>
    </div>

    <div v-else class="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-3">
      <div v-for="subj in assignedSubjects" :key="subj.id" class="overflow-hidden rounded-[24px] border border-[#DADCE0] bg-white shadow-sm transition hover:-translate-y-1 hover:shadow-md flex flex-col justify-between group">
        
        <div class="subject-card-banner relative h-40 overflow-hidden p-5 text-[#800000]" :class="`subject-card-banner--${getSubjectArtworkType(subj)}`">
          <StudyToolsArtwork :subject="subj" />
          <div class="relative z-10 max-w-[58%]">
            <p class="truncate text-sm font-medium text-[#5C0000]">{{ subj.code }}</p>
            <h3 class="mt-1 truncate text-xl font-medium tracking-tight text-[#800000]">{{ subj.title }}</h3>
            <p class="mt-1 truncate text-xs text-[#5C0000]">{{ subj.program || 'General Program' }}<span v-if="subj.section"> · {{ subj.section }}</span></p>
          </div>
        </div>

        <div class="p-5 space-y-4 bg-white flex-1 flex flex-col justify-between">
          <div class="grid grid-cols-3 gap-2 text-center">
            <router-link to="/instructor/upload-module" class="px-2 py-2 rounded-xl bg-[#F8F9FA] border border-[#DADCE0] text-[10px] font-bold text-[#800000] hover:bg-[#FDF0F0] transition">Modules</router-link>
            <router-link to="/instructor/create-activity" class="px-2 py-2 rounded-xl bg-[#F8F9FA] border border-[#DADCE0] text-[10px] font-bold text-[#800000] hover:bg-[#FDF0F0] transition">Activity</router-link>
            <router-link to="/instructor/submissions" class="px-2 py-2 rounded-xl bg-[#F8F9FA] border border-[#DADCE0] text-[10px] font-bold text-[#800000] hover:bg-[#FDF0F0] transition">Review</router-link>
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
