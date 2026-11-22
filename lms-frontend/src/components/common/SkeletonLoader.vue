<template>
  <div
    class="lms-skeleton"
    :class="[{ 'lms-skeleton--card': card }, `lms-skeleton--${variant}`]"
    role="status"
    aria-label="Loading content"
    aria-live="polite"
  >
    <template v-if="variant === 'table'">
      <div v-for="row in rows" :key="row" class="lms-skeleton__table-row">
        <span v-for="column in 4" :key="column" class="lms-skeleton__bar" :class="`lms-skeleton__bar--col-${column}`"></span>
      </div>
    </template>

    <template v-else-if="variant === 'cards'">
      <div v-for="cardIndex in 3" :key="cardIndex" class="lms-skeleton__card-item">
        <span class="lms-skeleton__bar lms-skeleton__bar--title"></span>
        <span class="lms-skeleton__bar"></span>
        <span class="lms-skeleton__bar lms-skeleton__bar--short"></span>
      </div>
    </template>

    <template v-else-if="variant === 'profile'">
      <div class="lms-skeleton__profile-head">
        <span class="lms-skeleton__avatar lms-skeleton__avatar--large"></span>
        <div class="lms-skeleton__stack">
          <span class="lms-skeleton__bar lms-skeleton__bar--title"></span>
          <span class="lms-skeleton__bar lms-skeleton__bar--short"></span>
        </div>
      </div>
      <div class="lms-skeleton__field-grid">
        <div v-for="field in 6" :key="field" class="lms-skeleton__stack">
          <span class="lms-skeleton__bar lms-skeleton__bar--label"></span>
          <span class="lms-skeleton__bar lms-skeleton__bar--field"></span>
        </div>
      </div>
    </template>

    <template v-else-if="variant === 'details'">
      <span class="lms-skeleton__hero"></span>
      <div class="lms-skeleton__stack">
        <span class="lms-skeleton__bar lms-skeleton__bar--title"></span>
        <span class="lms-skeleton__bar"></span>
        <span class="lms-skeleton__bar lms-skeleton__bar--short"></span>
      </div>
      <div class="lms-skeleton__card-grid">
        <div v-for="cardIndex in 2" :key="cardIndex" class="lms-skeleton__card-item">
          <span class="lms-skeleton__bar lms-skeleton__bar--title"></span>
          <span class="lms-skeleton__bar"></span>
          <span class="lms-skeleton__bar lms-skeleton__bar--short"></span>
        </div>
      </div>
    </template>

    <template v-else>
      <div v-for="row in rows" :key="row" class="lms-skeleton__list-row">
        <span class="lms-skeleton__avatar"></span>
        <div class="lms-skeleton__stack">
          <span class="lms-skeleton__bar lms-skeleton__bar--title"></span>
          <span class="lms-skeleton__bar lms-skeleton__bar--short"></span>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
defineProps({
  variant: { type: String, default: 'rows' },
  rows: { type: Number, default: 4 },
  card: Boolean,
})
</script>

<style scoped>
.lms-skeleton {
  display: grid;
  gap: 14px;
  width: 100%;
}
.lms-skeleton--card {
  padding: 20px;
  border: 1px solid #E7E9EE;
  border-radius: 12px;
  background: #FFFFFF;
}
.lms-skeleton__bar,
.lms-skeleton__avatar,
.lms-skeleton__hero {
  display: block;
  flex: none;
  border-radius: 6px;
  background: linear-gradient(90deg, #ECEEF1 20%, #F5F6F7 38%, #ECEEF1 62%);
  background-size: 300% 100%;
  animation: skeleton-shimmer 1.5s ease-in-out infinite;
}
.lms-skeleton__bar { width: 100%; height: 12px; }
.lms-skeleton__bar--title { width: 42%; height: 16px; }
.lms-skeleton__bar--short { width: 62%; }
.lms-skeleton__bar--label { width: 28%; height: 10px; }
.lms-skeleton__bar--field { height: 40px; border: 1px solid #E7E9EE; background-color: #FFFFFF; }
.lms-skeleton__avatar { width: 40px; height: 40px; border-radius: 50%; }
.lms-skeleton__avatar--large { width: 64px; height: 64px; }
.lms-skeleton__stack { display: grid; flex: 1; gap: 10px; }
.lms-skeleton__list-row { display: flex; align-items: center; gap: 14px; padding: 10px 0; }
.lms-skeleton__table-row { display: grid; grid-template-columns: 1.2fr 1.4fr .8fr .6fr; gap: 20px; padding: 14px 0; }
.lms-skeleton__bar--col-3 { width: 72%; }
.lms-skeleton__bar--col-4 { width: 60%; justify-self: end; }
.lms-skeleton--cards,
.lms-skeleton__card-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
.lms-skeleton__card-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.lms-skeleton__card-item { display: grid; align-content: start; gap: 16px; min-height: 112px; padding: 16px; border: 1px solid #E7E9EE; border-radius: 10px; background: #FFFFFF; }
.lms-skeleton__profile-head { display: flex; align-items: center; gap: 16px; padding-bottom: 18px; border-bottom: 1px solid #ECEEF1; }
.lms-skeleton__field-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.lms-skeleton__hero { height: 150px; border-radius: 10px; }
@keyframes skeleton-shimmer { to { background-position: -150% 0; } }
@media (max-width: 640px) {
  .lms-skeleton--cards,
  .lms-skeleton__card-grid { grid-template-columns: 1fr; }
  .lms-skeleton__field-grid { grid-template-columns: 1fr; }
  .lms-skeleton__table-row { grid-template-columns: 1fr 1.2fr .6fr; gap: 10px; }
  .lms-skeleton__bar--col-4 { display: none; }
}
@media (prefers-reduced-motion: reduce) {
  .lms-skeleton__bar,
  .lms-skeleton__avatar,
  .lms-skeleton__hero { animation: none; }
}
</style>
