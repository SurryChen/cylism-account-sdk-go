<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { CylismExpressiveButton, CylismPageHeader, CylismPanel, CylismText } from '@cylism/expressive-vue';
// This is the example BFF response, not an Account API client.
type AccessSummary = {status:string;roles:string[];permissions:Array<{key:string}>};
type Session = {profile:{sub:string;name?:string;email?:string};access:AccessSummary;csrf_token:string};
const session = ref<Session|null>(null), busy = ref(false), message = ref(''), orders = ref<string[]>([]);
async function refresh() {
 busy.value = true; message.value = '';
 try {
  const response = await fetch('/api/me', {credentials:'same-origin'});
  if(response.status===401){ session.value=null; return; }
  if(!response.ok) throw new Error('加载登录信息失败');
  session.value=await response.json();
 } catch(error){message.value=error instanceof Error?error.message:'请求失败';} finally{busy.value=false;}
}
function login(provider=''){window.location.assign('/auth/login'+(provider?'?provider='+encodeURIComponent(provider):''));}
async function loadOrders(){
 busy.value=true; message.value='';
 try{ const response=await fetch('/api/orders'); if(!response.ok) throw new Error(response.status===403?'当前账号没有 orders:read 权限':'读取失败'); orders.value=(await response.json()).items; }
 catch(error){message.value=error instanceof Error?error.message:'请求失败';}finally{busy.value=false;}
}
async function logout(){
 if(!session.value)return;busy.value=true;
 try{const response=await fetch('/api/logout',{method:'POST',headers:{'X-CSRF-Token':session.value.csrf_token}});if(!response.ok)throw new Error('退出失败');session.value=null;orders.value=[];}
 catch(error){message.value=error instanceof Error?error.message:'请求失败';}finally{busy.value=false;}
}
onMounted(refresh);
</script>
<template>
 <main class="sdk-demo">
  <CylismPageHeader title="Account SDK 接入示例" />
  <CylismPanel v-if="!session" title="登录你的应用">
   <div class="sdk-demo__actions">
    <CylismExpressiveButton :loading="busy" @click="login()">登录</CylismExpressiveButton>
    <CylismExpressiveButton variant="tonal" @click="login('github')">GitHub</CylismExpressiveButton>
    <CylismExpressiveButton variant="tonal" @click="login('google')">Google</CylismExpressiveButton>
   </div>
  </CylismPanel>
  <CylismPanel v-else :title="session.profile.name || '我的账号'">
   <CylismText>{{ session.profile.email || session.profile.sub }}</CylismText>
   <CylismText>角色：{{session.access.roles.join('、') || '无'}}</CylismText>
   <div class="sdk-demo__actions">
    <CylismExpressiveButton :disabled="session.access.status !== 'active' || !session.access.permissions.some(permission => permission.key === 'orders:read')" :loading="busy" @click="loadOrders">读取订单</CylismExpressiveButton>
    <CylismExpressiveButton variant="tonal" :disabled="busy" @click="refresh">刷新权限</CylismExpressiveButton>
    <CylismExpressiveButton variant="text" :disabled="busy" @click="logout">退出登录</CylismExpressiveButton>
   </div>
   <CylismText v-for="order in orders" :key="order">{{order}}</CylismText>
  </CylismPanel>
  <CylismText v-if="message" tone="error">{{message}}</CylismText>
 </main>
</template>
<style scoped>
.sdk-demo{max-width:960px;margin:48px auto;padding:24px;display:grid;gap:24px;}
.sdk-demo__actions{display:flex;flex-wrap:wrap;gap:12px;margin-top:24px;}
</style>
