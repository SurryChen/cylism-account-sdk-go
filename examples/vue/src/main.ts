import { createApp } from 'vue';
import { createCylismUI } from '@cylism/expressive-vue';
import 'vuetify/styles';
import '@cylism/expressive-vue/style.css';
import App from './App.vue';
createApp(App).use(createCylismUI()).mount('#app');
