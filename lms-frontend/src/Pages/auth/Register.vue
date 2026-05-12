<template>
  <div class="w-full max-w-md">
    <div class="text-center mb-8">
      <div class="w-16 h-16 rounded-full bg-[#800000] flex items-center justify-center mx-auto mb-4">
        <span class="text-[#D4AF37] font-bold text-xl">MSU</span>
      </div>
      <h1 class="text-2xl font-bold text-[#800000]">Create an Account</h1>
      <p class="text-sm text-[#6B7280] mt-1">Mindanao State University LMS</p>
    </div>
    <div class="rounded-2xl border border-[#E7DCC3] bg-white shadow-sm p-8 space-y-4">
      <div>
        <label class="block text-sm font-medium mb-1.5">Full Name</label>
        <input type="text" placeholder="Juan Dela Cruz"
          class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-[#FAFAF7] focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000]" />
      </div>
      <div>
        <label class="block text-sm font-medium mb-1.5">Email</label>
        <input type="email" placeholder="you@msu.edu.ph"
          class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-[#FAFAF7] focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000]" />
      </div>
      <div>
        <label class="block text-sm font-medium mb-1.5">Password</label>
        <input type="password" placeholder="••••••••"
          class="w-full border border-[#E7DCC3] rounded-lg px-4 py-2.5 text-sm bg-[#FAFAF7] focus:outline-none focus:border-[#800000] focus:ring-1 focus:ring-[#800000]" />
      </div>
      <button class="w-full rounded-lg bg-[#800000] px-5 py-3 text-sm font-semibold text-white hover:bg-[#5A0000] transition">
        Register
      </button>
      <p class="text-center text-xs text-[#6B7280]">
        Already have an account?
        <router-link to="/login" class="text-[#800000] font-medium hover:underline">Sign In</router-link>
      </p>
    </div>
  </div>
</template>
