<template>
  <div class="space-y-6">
    <!-- Welcome -->
    <div>
      <h2 class="text-xl font-bold text-[#1F1F1F]">Welcome back, {{ user.name }}! 👋</h2>
      <p class="text-sm text-[#6B7280] mt-0.5">Here's your academic overview for this semester.</p>
    </div>

    <!-- Stat Cards -->
    <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      <StatCard title="Enrolled Subjects" value="4" description="Active this semester" icon="📚" iconBg="#FFF8E7" />
      <StatCard title="Pending Activities" value="3" description="Due this week" icon="📝" iconBg="#FEF3C7" />
      <StatCard title="Submitted Activities" value="12" description="Completed so far" icon="✅" iconBg="#F0FDF4" />
      <StatCard title="Average Grade" value="87%" description="Across all subjects" icon="🎓" iconBg="#FFF1F2" />
    </div>

    <!-- Content Row -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
      <!-- Recent Subjects -->
      <CardPanel title="My Subjects">
        <div class="space-y-3">
          <div v-for="subj in subjects" :key="subj.id"
            class="flex items-center justify-between p-3 rounded-xl bg-[#FAFAF7] border border-[#E7DCC3] hover:border-[#D4AF37] transition cursor-pointer">
            <div>
              <p class="text-sm font-semibold text-[#1F1F1F]">{{ subj.code }} - {{ subj.name }}</p>
              <p class="text-xs text-[#6B7280]">{{ subj.instructor }}</p>
            </div>
            <span class="text-xs font-medium text-[#800000] bg-[#FFF8E7] border border-[#E7DCC3] px-2 py-0.5 rounded-full">
              {{ subj.units }} units
            </span>
          </div>
        </div>
        <template #header-action>
          <router-link to="/student/subjects" class="text-xs text-[#800000] hover:underline font-medium">View All</router-link>
        </template>
      </CardPanel>

      <!-- Pending Activities -->
      <CardPanel title="Pending Activities">
        <div class="space-y-3">
          <div v-for="act in pendingActivities" :key="act.id"
            class="flex items-start gap-3 p-3 rounded-xl bg-[#FAFAF7] border border-[#E7DCC3]">
            <div class="w-8 h-8 rounded-lg bg-[#FFF8E7] flex items-center justify-center text-sm shrink-0 border border-[#E7DCC3]">
              {{ act.icon }}
            </div>
            <div class="flex-1 min-w-0">
              <p class="text-sm font-semibold text-[#1F1F1F] truncate">{{ act.title }}</p>
              <p class="text-xs text-[#6B7280]">{{ act.subject }}</p>
            </div>
            <span class="text-xs text-red-500 shrink-0 font-medium">Due: {{ act.due }}</span>
          </div>
        </div>
        <template #header-action>
          <router-link to="/student/activities" class="text-xs text-[#800000] hover:underline font-medium">View All</router-link>
        </template>
      </CardPanel>
    </div>

    <!-- Grades Summary -->
    <CardPanel title="Grade Summary">
      <table class="w-full text-sm">
        <thead>
          <tr class="text-left text-xs text-[#6B7280] border-b border-[#E7DCC3]">
            <th class="pb-3 font-medium">Subject</th>
            <th class="pb-3 font-medium">Instructor</th>
            <th class="pb-3 font-medium">Grade</th>
            <th class="pb-3 font-medium">Status</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-[#E7DCC3]">
          <tr v-for="g in grades" :key="g.subject" class="hover:bg-[#FAFAF7] transition">
            <td class="py-3 font-medium text-[#1F1F1F]">{{ g.subject }}</td>
            <td class="py-3 text-[#6B7280]">{{ g.instructor }}</td>
            <td class="py-3 font-bold text-[#800000]">{{ g.grade }}</td>
            <td class="py-3">
              <span :class="g.status === 'Passing' ? 'text-green-600 bg-green-50' : 'text-yellow-600 bg-yellow-50'"
                class="text-xs px-2 py-0.5 rounded-full font-medium">
                {{ g.status }}
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </CardPanel>
  </div>
</template>

<script setup>
import StatCard from '@/components/common/StatCard.vue'
import CardPanel from '@/components/common/CardPanel.vue'

const user = JSON.parse(localStorage.getItem('user') || '{ "name": "Student" }')

const subjects = [
  { id: 1, code: 'IT101', name: 'Introduction to Computing', instructor: 'Prof. Santos', units: 3 },
  { id: 2, code: 'IT201', name: 'Database Management', instructor: 'Prof. Reyes', units: 3 },
  { id: 3, code: 'IT301', name: 'Web Development', instructor: 'Prof. Cruz', units: 3 },
  { id: 4, code: 'IT401', name: 'Capstone Project', instructor: 'Prof. Mendoza', units: 6 },
]

const pendingActivities = [
  { id: 1, title: 'Essay 1', subject: 'IT101', due: 'Jan 15', icon: '📄' },
  { id: 2, title: 'Assignment 2 - Make a Query', subject: 'IT201', due: 'Jan 18', icon: '💾' },
  { id: 3, title: 'Lab Exercise 3', subject: 'IT301', due: 'Jan 20', icon: '💻' },
]

const grades = [
  { subject: 'IT101', instructor: 'Prof. Santos', grade: '88%', status: 'Passing' },
  { subject: 'IT201', instructor: 'Prof. Reyes', grade: '91%', status: 'Passing' },
  { subject: 'IT301', instructor: 'Prof. Cruz', grade: '76%', status: 'Passing' },
  { subject: 'IT401', instructor: 'Prof. Mendoza', grade: '—', status: 'In Progress' },
]
</script>
