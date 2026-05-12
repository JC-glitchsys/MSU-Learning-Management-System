<template>
  <div class="space-y-6">
    <div>
      <h2 class="text-xl font-bold text-[#1F1F1F]">Good day, {{ user.name }}! 👨‍🏫</h2>
      <p class="text-sm text-[#6B7280] mt-0.5">Manage your subjects, modules, and student activities.</p>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      <StatCard title="Handled Subjects" value="2" description="This semester" icon="📚" iconBg="#FFF8E7" />
      <StatCard title="Uploaded Modules" value="8" description="Across all subjects" icon="📤" iconBg="#EFF6FF" />
      <StatCard title="Created Activities" value="3" description="Published" icon="✏️" iconBg="#FEF3C7" />
      <StatCard title="Pending Submissions" value="5" description="Needs grading" icon="📥" iconBg="#FFF1F2" />
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
      <!-- Subjects -->
      <CardPanel title="My Subjects">
        <div class="space-y-3">
          <div v-for="subj in subjects" :key="subj.id"
            class="p-4 rounded-xl bg-[#FAFAF7] border border-[#E7DCC3] hover:border-[#D4AF37] transition">
            <div class="flex items-start justify-between">
              <div>
                <p class="text-sm font-semibold text-[#1F1F1F]">{{ subj.code }} - {{ subj.name }}</p>
                <p class="text-xs text-[#6B7280] mt-0.5">{{ subj.enrolled }} students enrolled</p>
              </div>
              <span class="text-xs bg-[#800000] text-white px-2 py-0.5 rounded-full font-medium shrink-0 ml-2">
                {{ subj.section }}
              </span>
            </div>
          </div>
        </div>
      </CardPanel>

      <!-- Recent Submissions -->
      <CardPanel title="Recent Submissions">
        <div class="space-y-3">
          <div v-for="sub in submissions" :key="sub.id"
            class="flex items-center gap-3 p-3 rounded-xl bg-[#FAFAF7] border border-[#E7DCC3]">
            <div class="w-8 h-8 rounded-full bg-[#800000] flex items-center justify-center text-white text-xs font-bold shrink-0">
              {{ sub.initials }}
            </div>
            <div class="flex-1 min-w-0">
              <p class="text-sm font-semibold text-[#1F1F1F] truncate">{{ sub.student }}</p>
              <p class="text-xs text-[#6B7280]">{{ sub.activity }} · {{ sub.date }}</p>
            </div>
            <span :class="sub.graded ? 'text-green-600 bg-green-50' : 'text-yellow-600 bg-yellow-50'"
              class="text-xs px-2 py-0.5 rounded-full font-medium shrink-0">
              {{ sub.graded ? 'Graded' : 'Pending' }}
            </span>
          </div>
        </div>
        <template #header-action>
          <router-link to="/instructor/submissions" class="text-xs text-[#800000] hover:underline font-medium">View All</router-link>
        </template>
      </CardPanel>
    </div>

    <!-- Quick Actions -->
    <CardPanel title="Quick Actions">
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <router-link to="/instructor/upload-module"
          class="flex flex-col items-center gap-2 p-4 rounded-xl border border-[#E7DCC3] bg-[#FAFAF7] hover:border-[#800000] hover:bg-[#FFF8E7] transition text-center">
          <span class="text-2xl">📤</span>
          <span class="text-xs font-semibold text-[#1F1F1F]">Upload Module</span>
        </router-link>
        <router-link to="/instructor/create-activity"
          class="flex flex-col items-center gap-2 p-4 rounded-xl border border-[#E7DCC3] bg-[#FAFAF7] hover:border-[#800000] hover:bg-[#FFF8E7] transition text-center">
          <span class="text-2xl">✏️</span>
          <span class="text-xs font-semibold text-[#1F1F1F]">Create Activity</span>
        </router-link>
        <router-link to="/instructor/submissions"
          class="flex flex-col items-center gap-2 p-4 rounded-xl border border-[#E7DCC3] bg-[#FAFAF7] hover:border-[#800000] hover:bg-[#FFF8E7] transition text-center">
          <span class="text-2xl">📥</span>
          <span class="text-xs font-semibold text-[#1F1F1F]">View Submissions</span>
        </router-link>
        <router-link to="/instructor/grade-submission"
          class="flex flex-col items-center gap-2 p-4 rounded-xl border border-[#E7DCC3] bg-[#FAFAF7] hover:border-[#800000] hover:bg-[#FFF8E7] transition text-center">
          <span class="text-2xl">🎯</span>
          <span class="text-xs font-semibold text-[#1F1F1F]">Grade Submission</span>
        </router-link>
      </div>
    </CardPanel>
  </div>
</template>

<script setup>
import StatCard from '@/components/common/StatCard.vue'
import CardPanel from '@/components/common/CardPanel.vue'

const user = JSON.parse(localStorage.getItem('user') || '{ "name": "Instructor" }')

const subjects = [
  { id: 1, code: 'IT101', name: 'Introduction to Computing', section: 'BSIT-1A', enrolled: 35 },
  { id: 2, code: 'IT201', name: 'Database Management', section: 'BSIT-2B', enrolled: 30 },
]

const submissions = [
  { id: 1, student: 'Juan Dela Cruz', activity: 'Essay 1', date: 'Jan 14', graded: false, initials: 'JD' },
  { id: 2, student: 'Maria Santos', activity: 'Essay 1', date: 'Jan 14', graded: true, initials: 'MS' },
  { id: 3, student: 'Pedro Reyes', activity: 'Assignment 2', date: 'Jan 13', graded: false, initials: 'PR' },
]
</script>
