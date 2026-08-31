import { h } from 'vue'
import { useData } from 'vitepress'
import type { Theme } from 'vitepress'
import DefaultTheme from 'vitepress/theme-without-fonts'
import ForkbombBrand from './components/ForkbombBrand.vue'
import ProductFooter from './components/ProductFooter.vue'
import HomePage from './components/HomePage.vue'
import './forkbomb.css'
import './style.css'

export default {
  extends: DefaultTheme,
  Layout: () => {
    const { frontmatter } = useData()

    return h(DefaultTheme.Layout, null, {
      'nav-bar-title-before': () => h(ForkbombBrand),
      'home-hero-before': () => frontmatter.value.layout === 'home' ? h(HomePage) : null,
      'layout-bottom': () => h(ProductFooter),
    })
  },
} satisfies Theme
