<script lang="ts">
import Vue from 'vue';
import PreferencesNavItem from '@/components/Preferences/ModalNavItem.vue';

export default Vue.extend({
  name:       'preferences-nav',
  components: { NavItem: PreferencesNavItem },
  props:      {
    currentNavItem: {
      type:     String,
      required: true
    },
    navItems: {
      type:     Array,
      required: true
    }
  },
  methods: {
    navClicked(tabName: string) {
      this.$emit('nav-changed', tabName);
    }
  }
});
</script>

<template>
  <div class="preferences-nav">
    <nav-item
      v-for="navItem in navItems"
      :key="navItem"
      :name="navItem"
      :active="currentNavItem === navItem"
      @click="navClicked"
    >
      {{ navItem }}
    </nav-item>
  </div>
</template>

<style lang="scss" scoped>
  .preferences-nav {
    display: flex;
    flex-direction: column;
    height: 100%;
    border-right: 1px solid var(--header-border);
    padding-top: 0.75rem;
  }
</style>
