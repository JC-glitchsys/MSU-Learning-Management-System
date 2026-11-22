<template>
  <div class="space-y-8 animate-fade-in">
    <div>
      <h2 class="text-3xl md:text-4xl font-bold text-[#800000] tracking-tight">Classwork Assignments</h2>
      <p class="text-[#5F6368] mt-1 font-medium text-sm">Review published course requirements and submit your evaluation portfolio sheets.</p>
    </div>

    <div v-if="loading" class="p-12 text-center bg-white rounded-[28px] border border-[#DADCE0] shadow-sm">
      <span class="w-6 h-6 border-4 border-[#800000]/30 border-t-[#800000] rounded-full animate-spin inline-block"></span>
    </div>
    <div v-else-if="activities.length === 0" class="p-12 text-center bg-white rounded-[28px] border border-[#DADCE0] text-[#5F6368] text-sm font-bold">
      🎉 No active classwork requirements found across your enrolled streams.
    </div>

    <div v-else class="grid grid-cols-1 gap-5 max-w-4xl">
      <div v-for="act in activities" :key="act.id" class="bg-white rounded-[24px] border border-[#DADCE0] p-5 shadow-sm space-y-4">
        
        <div class="flex flex-wrap items-start justify-between gap-3 border-b border-[#DADCE0]/50 pb-3">
          <div>
            <span class="inline-block text-[10px] font-black tracking-wider uppercase text-[#800000] bg-[#FDF0F0] border border-[#DADCE0] px-2.5 py-0.5 rounded-full mb-1.5">{{ act.subjectCode }}</span>
            <h3 class="text-base font-bold text-[#202124] tracking-tight">{{ act.title }}</h3>
            <p class="text-xs text-[#5F6368] mt-1 font-medium leading-relaxed whitespace-pre-line">{{ act.instructions }}</p>
          </div>
          <div class="text-right shrink-0 space-y-1">
            <span class="inline-block text-[10px] font-bold text-[#D93025] bg-white border border-[#DADCE0] px-2.5 py-0.5 rounded-full">Due {{ act.dueDate }}</span>
            <p class="text-[11px] text-[#5F6368] font-mono font-bold block">Scale: {{ act.points }} Pts</p>
          </div>
        </div>

        <div class="bg-[#F8F9FA] rounded-xl p-4 border border-[#DADCE0]/60">
          <div v-if="getSubmission(act.id)" class="space-y-3">
            <div class="flex items-center justify-between">
              <span class="text-xs font-bold text-[#188038] bg-white border border-[#DADCE0] px-3 py-1 rounded-full uppercase tracking-wider">Handed In</span>
              <span v-if="getSubmission(act.id).status === 'graded'" class="text-xs font-bold text-[#800000] bg-[#FDF0F0] border border-[#DADCE0] px-3 py-1 rounded-full">Graded Mark: {{ getSubmission(act.id).grade }}</span>
            </div>
            
            <div class="text-xs text-[#202124] bg-white p-3 rounded-lg border border-[#DADCE0]/40">
              <p class="font-mono text-[11px] text-[#5F6368] mb-1">Answer Payload Text log:</p>
              <p class="whitespace-pre-wrap">{{ getSubmission(act.id).answerText || 'None' }}</p>
              <p v-if="getSubmission(act.id).fileUrl" class="mt-2 text-[#800000] font-bold truncate">Attachment: <a :href="getSubmission(act.id).fileUrl" target="_blank" class="underline hover:text-[#5C0000]">{{ getSubmission(act.id).fileUrl }}</a></p>
            </div>

              <button v-if="getSubmission(act.id).status !== 'graded'" @click="activateForm(act)" class="text-xs font-bold text-[#800000] hover:underline">
                Modify Upload Package Before Grading
            </button>
          </div>

          <div v-if="!getSubmission(act.id) || activeEditId === act.id" class="space-y-3.5">
            <h4 class="text-xs font-bold text-[#202124] uppercase tracking-wider">Turn In Work Package</h4>
            <div class="space-y-3">
              <textarea v-model="submitForm.answerText" rows="3" placeholder="Type or paste your response statement text logs here..." class="w-full rounded-[12px] border border-[#DADCE0] bg-white px-4 py-3 text-xs text-[#202124] outline-none transition focus:border-[#800000] resize-none"></textarea>
              <input v-model="submitForm.fileUrl" type="url" placeholder="Attachment Link URL (e.g., Google Drive link, GitHub repository, cloud asset)" class="w-full rounded-[12px] border border-[#DADCE0] bg-white px-4 py-2.5 text-xs outline-none focus:border-[#800000]" />
              
              <div class="flex items-center justify-end gap-3 pt-2">
                <button v-if="activeEditId === act.id" type="button" @click="activeEditId = null" class="text-xs font-bold text-[#5F6368]">Cancel</button>
                <button @click="executeWorkSubmission(act)" :disabled="submitting" class="rounded-full bg-[#800000] px-5 py-2 text-xs font-bold text-white shadow-sm hover:bg-[#5C0000] transition disabled:opacity-50">
                  {{ submitting ? 'Uploading package...' : (activeEditId === act.id ? 'Push Update Package' : 'Turn In Assignment') }}
                </button>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { collection, query, where, getDocs, addDoc, doc, updateDoc, serverTimestamp } from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import { showResult } from '@/utils/resultMessage'

const user = JSON.parse(localStorage.getItem('user') || '{}')
const loading = ref(true)
const submitting = ref(false)
const activities = ref([])
const studentSubmissions = ref([])

const activeEditId = ref(null)
const submitForm = ref({ answerText: '', fileUrl: '' })

const fetchClassworkArchitecture = async () => {
  loading.value = true
  try {
    // 1. Get student enrollments mapping arrays
    const enrollSnap = await getDocs(query(collection(db, 'enrollments'), where('studentId', '==', user.uid)))
    const subjectSnap = await getDocs(collection(db, 'subjects'))
    const activeSubjectIds = new Set(subjectSnap.docs.filter((subject) => subject.data().archived !== true).map((subject) => subject.id))
    const enrolledSubjectIds = enrollSnap.docs.filter(d => d.data().archived !== true && activeSubjectIds.has(d.data().subjectId)).map(d => d.data().subjectId)

    if (enrolledSubjectIds.length > 0) {
      // 2. Fetch relevant activities across streams
      // Gamit muna tayo ng structured layout map dahil may limitasyon si Firestore in array rules
      const actSnap = await getDocs(collection(db, 'activities'))
      activities.value = actSnap.docs
        .map(d => ({ id: d.id, ...d.data() }))
        .filter(act => act.archived !== true && enrolledSubjectIds.includes(act.subjectId))
    }

    // 3. Get existing student submissions archive
    const subSnap = await getDocs(query(collection(db, 'submissions'), where('studentId', '==', user.uid)))
    studentSubmissions.value = subSnap.docs.map(d => ({ id: d.id, ...d.data() }))
  } catch (err) {
    console.error(err)
  } finally {
    loading.value = false
  }
}

const getSubmission = (activityId) => studentSubmissions.value.find(s => s.activityId === activityId)

const activateForm = (act) => {
  const current = getSubmission(act.id)
  activeEditId.value = act.id
  submitForm.value = { answerText: current?.answerText || '', fileUrl: current?.fileUrl || '' }
}

const executeWorkSubmission = async (act) => {
  if (!submitForm.value.answerText.trim() && !submitForm.value.fileUrl.trim()) {
    showResult('Response Required', 'Add written text or a file link before submitting.', 'info')
    return
  }
  submitting.value = true
  try {
    const existing = getSubmission(act.id)
    const payload = {
      answerText: submitForm.value.answerText,
      fileUrl: submitForm.value.fileUrl,
      submittedAt: serverTimestamp()
    }

    if (existing) {
      await updateDoc(doc(db, 'submissions', existing.id), payload)
    } else {
      const newDoc = {
        activityId: act.id,
        subjectId: act.subjectId,
        subjectCode: act.subjectCode,
        subjectTitle: act.subjectTitle,
        studentId: user.uid,
        studentName: user.name,
        studentEmail: user.email,
        ...payload,
        status: 'submitted',
        grade: null,
        feedback: ''
      }
      await addDoc(collection(db, 'submissions'), newDoc)
    }

    activeEditId.value = null
    submitForm.value = { answerText: '', fileUrl: '' }
    await fetchClassworkArchitecture()
    showResult('Work Submitted', 'Your response has been sent to your instructor.')
  } catch (err) {
    showResult('Could Not Submit Work', 'Please try again.', 'error')
  } finally {
    submitting.value = false
  }
}

onMounted(fetchClassworkArchitecture)
</script>

<style scoped>
.animate-fade-in { animation: fadeIn 0.2s ease-out forwards; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
</style>
