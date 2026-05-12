<template>
  <div class="space-y-6">
    <div>
      <h2 class="text-xl font-bold text-[#1F1F1F]">Admin Overview</h2>
      <p class="text-sm text-[#6B7280] mt-0.5">System-wide statistics and management.</p>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      <StatCard title="Total Students" value="248" description="Enrolled this semester" icon="🎓" iconBg="#FFF8E7" />
      <StatCard title="Total Instructors" value="32" description="Active faculty" icon="👨‍🏫" iconBg="#EFF6FF" />
      <StatCard title="Total Courses" value="12" description="Offered programs" icon="📋" iconBg="#F0FDF4" />
      <StatCard title="Total Subjects" value="56" description="This semester" icon="📚" iconBg="#FFF1F2" />
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
      <!-- Recent Enrollments -->
      <div class="lg:col-span-2">
        <CardPanel title="Recent Enrollments">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-xs text-[#6B7280] border-b border-[#E7DCC3]">
                <th class="pb-3 font-medium">Student</th>
                <th class="pb-3 font-medium">Subject</th>
                <th class="pb-3 font-medium">Status</th>
                <th class="pb-3 font-medium">Date</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-[#E7DCC3]">
              <tr v-for="e in enrollments" :key="e.id" class="hover:bg-[#FAFAF7] transition">
                <td class="py-3 font-medium text-[#1F1F1F]">{{ e.student }}</td>
                <td class="py-3 text-[#6B7280]">{{ e.subject }}</td>
                <td class="py-3">
                  <span :class="e.status === 'active' ? 'text-green-600 bg-green-50' : e.status === 'pending' ? 'text-yellow-600 bg-yellow-50' : 'text-red-600 bg-red-50'"
                    class="text-xs px-2 py-0.5 rounded-full font-medium capitalize">
                    {{ e.status }}
                  </span>
                </td>
                <td class="py-3 text-[#6B7280] text-xs">{{ e.date }}</td>
              </tr>
            </tbody>
          </table>
        </CardPanel>
      </div>

      <!-- Quick Links -->
      <div class="space-y-3">
        <CardPanel title="Quick Management">
          <div class="space-y-2">
            <router-link v-for="link in quickLinks" :key="link.to" :to="link.to"
              class="flex items-center gap-3 p-3 rounded-xl bg-[#FAFAF7] border border-[#E7DCC3] hover:border-[#800000] hover:bg-[#FFF8E7] transition">
              <span class="text-lg">{{ link.icon }}</span>
              <span class="text-sm font-medium text-[#1F1F1F]">{{ link.label }}</span>
            </router-link>
          </div>
        </CardPanel>
      </div>
    </div>
  </div>
</template>

<script setup>
import StatCard from '@/components/common/StatCard.vue'
import CardPanel from '@/components/common/CardPanel.vue'

const enrollments = [
  { id: 1, student: 'Juan Dela Cruz', subject: 'IT101 - Intro to Computing', status: 'active', date: 'Dec 7, 2025' },
  { id: 2, student: 'Maria Santos', subject: 'IT201 - Database Mgmt', status: 'active', date: 'Dec 8, 2025' },
  { id: 3, student: 'Pedro Reyes', subject: 'IT301 - Web Development', status: 'pending', date: 'Dec 9, 2025' },
  { id: 4, student: 'Ana Lim', subject: 'IT401 - Capstone', status: 'active', date: 'Dec 10, 2025' },
]

const quickLinks = [
  { to: '/admin/students', label: 'Manage Students', icon: '🎓' },
  { to: '/admin/instructors', label: 'Manage Instructors', icon: '👨‍🏫' },
  { to: '/admin/courses', label: 'Manage Courses', icon: '📋' },
  { to: '/admin/subjects', label: 'Manage Subjects', icon: '📚' },
  { to: '/admin/enroll', label: 'Enroll Students', icon: '📝' },
  { to: '/admin/reports', label: 'View Reports', icon: '📊' },
]
</script>
