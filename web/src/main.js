import { createApp } from 'vue'
import App from './App.vue'
import router from './router/index.js'

import './styles/tokens.css'
import './styles/base.css'
import './styles/layout.css'
import './styles/desktop.css'

createApp(App).use(router).mount('#app')
