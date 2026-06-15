import { supabase, smartRules } from './config.js';
import * as api from './api.js';

// 全局状态
const state = {
    currentUser: null,
    isSignUpMode: false,
    myCategories: [],
    selectedFilterCats: new Set()
};

// 页面初始化
document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById('dateInput').value = new Date().toISOString().split('T')[0];
    bindEvents(); // 绑定所有 DOM 事件
    
    try {
        const { data: { session }, error } = await supabase.auth.getSession();
        if (error) throw error;
        if (session && session.user) {
            initApp(session.user);
        } else {
            showAuthCard();
        }
    } catch (e) {
        alert("初始化失败: " + e.message);
        showAuthCard();
    }
});

// 绑定页面事件（消除 HTML 中的 onclick）
function bindEvents() {
    document.getElementById('toggleAuthModeBtn').addEventListener('click', toggleAuthMode);
    document.getElementById('authForm').addEventListener('submit', handleAuth);
    document.getElementById('logoutBtn').addEventListener('click', async () => {
        await api.logoutUser();
        location.reload();
    });
    document.getElementById('recordForm').addEventListener('submit', handleRecordSubmit);
    document.getElementById('addCatBtn').addEventListener('click', handleAddCategory);
    document.getElementById('descInput').addEventListener('input', (e) => autoCategory(e.target.value));
    document.getElementById('filterMonth').addEventListener('change', fetchAndRenderRecords);
    
    // 事件委托：处理动态渲染的删除按钮和复选框
    document.getElementById('customCatList').addEventListener('click', handleDeleteCategory);
    document.getElementById('historyContainer').addEventListener('click', handleDeleteRecord);
    document.getElementById('filterCategories').addEventListener('change', handleFilterCatChange);
}

// --- 认证 UI 逻辑 ---
function showAuthCard() {
    document.getElementById('authCard').classList.remove('hidden-section');
    document.getElementById('appCard').classList.add('hidden-section');
}

function toggleAuthMode() {
    state.isSignUpMode = !state.isSignUpMode;
    document.getElementById('authTitle').innerText = state.isSignUpMode ? '注册新账户' : '欢迎回来';
    document.getElementById('authSubtitle').innerText = state.isSignUpMode ? '请输入邮箱、密码及邀请码进行注册' : '请输入您的账户登录记账系统';
    document.getElementById('authSubmitBtn').innerText = state.isSignUpMode ? '注 册' : '登 录';
    document.getElementById('toggleAuthModeBtn').innerText = state.isSignUpMode ? '已有账号？去登录' : '没有账号？去注册';
    document.getElementById('inviteKeyField').classList.toggle('hidden-section', !state.isSignUpMode);
}

async function handleAuth(event) {
    event.preventDefault();
    const btn = document.getElementById('authSubmitBtn');
    btn.disabled = true;
    btn.innerText = '处理中...';

    const email = document.getElementById('authEmail').value;
    const password = document.getElementById('authPassword').value;
    
    try {
        if (state.isSignUpMode) {
            const inviteKey = document.getElementById('authInviteKey').value;
            const user = await api.registerUser(email, password, inviteKey);
            alert('注册成功！');
            initApp(user);
        } else {
            const user = await api.loginUser(email, password);
            initApp(user);
        }
    } catch (err) {
        alert('认证失败：' + err.message);
    } finally {
        btn.disabled = false;
        btn.innerText = state.isSignUpMode ? '注 册' : '登 录';
    }
}

// --- 主应用 UI 逻辑 ---
async function initApp(user) {
    state.currentUser = user;
    document.getElementById('userEmailTag').innerText = user.email;
    document.getElementById('authCard').classList.add('hidden-section');
    document.getElementById('appCard').classList.remove('hidden-section');
    
    await fetchAndRenderCategories();
    await fetchAndRenderRecords();
}

async function fetchAndRenderCategories() {
    try {
        state.myCategories = await api.getCategories();
        renderCategoryComponent();
    } catch (err) {
        console.error("加载分类失败", err);
    }
}

function renderCategoryComponent() {
    document.getElementById('categorySelect').innerHTML = state.myCategories.map(c => `<option value="${c.name}">${c.icon} ${c.name}</option>`).join('');
    
    const catListHTML = state.myCategories.length === 0 ? '<span class="text-[10px] text-slate-400">暂无分类</span>' :
        state.myCategories.map(c => `
            <span class="inline-flex items-center gap-1 bg-slate-100 text-slate-700 text-xs px-2 py-1 rounded-full border border-slate-200">
                <span>${c.icon} ${c.name}</span>
                <button data-action="delete-cat" data-id="${c.id}" class="text-slate-400 hover:text-red-500 font-bold ml-0.5">×</button>
            </span>
        `).join('');
    document.getElementById('customCatList').innerHTML = catListHTML;

    document.getElementById('filterCategories').innerHTML = state.myCategories.map(c => `
        <label class="flex items-center gap-1 bg-white px-2 py-1 rounded border border-slate-200 cursor-pointer hover:bg-slate-50">
            <input type="checkbox" value="${c.name}" ${state.selectedFilterCats.has(c.name) ? 'checked' : ''} class="rounded text-blue-600 focus:ring-0">
            <span class="text-xs">${c.name}</span>
        </label>
    `).join('');
}

function autoCategory(text) {
    const tip = document.getElementById('matchTip');
    const select = document.getElementById('categorySelect');
    if (!text) return tip.classList.add('invisible');

    for (const [category, keywords] of Object.entries(smartRules)) {
        if (keywords.some(k => text.toLowerCase().includes(k.toLowerCase())) && state.myCategories.some(c => c.name === category)) {
            select.value = category;
            return tip.classList.remove('invisible');
        }
    }
    tip.classList.add('invisible');
}

async function handleAddCategory() {
    const input = document.getElementById('newCatInput');
    const name = input.value.trim();
    if (!name) return;
    if (state.myCategories.some(c => c.name === name)) return alert('该分类名称已存在！');

    try {
        await api.addCategory(state.currentUser.id, name);
        input.value = '';
        fetchAndRenderCategories();
    } catch (err) { alert(err.message); }
}

async function handleDeleteCategory(e) {
    if (e.target.dataset.action === 'delete-cat') {
        if (!confirm('确定删除该分类吗？')) return;
        await api.deleteCategory(e.target.dataset.id);
        fetchAndRenderCategories();
    }
}

function handleFilterCatChange(e) {
    if (e.target.type === 'checkbox') {
        e.target.checked ? state.selectedFilterCats.add(e.target.value) : state.selectedFilterCats.delete(e.target.value);
        fetchAndRenderRecords(); 
    }
}

async function fetchAndRenderRecords() {
    const monthVal = document.getElementById('filterMonth').value; 
    const container = document.getElementById('historyContainer');
    
    try {
        const records = await api.getRecords(monthVal, Array.from(state.selectedFilterCats));
        
        if (records.length > 0) {
            const sum = records.reduce((acc, curr) => acc + parseFloat(curr.amount), 0);
            document.getElementById('totalSumTag').innerText = `￥${sum.toFixed(2)}`;
            document.getElementById('totalCountTag').innerText = `${records.length} 笔`;

            container.innerHTML = records.map(r => `
                <div class="flex justify-between items-center bg-slate-50 p-3 rounded-xl border border-slate-200 shadow-sm hover:bg-slate-100 transition-colors">
                    <div>
                        <p class="text-sm font-semibold text-slate-800">${r.description}</p>
                        <p class="text-[11px] text-slate-400 mt-0.5">${r.date} · <span class="bg-blue-50 text-blue-600 px-1.5 py-0.5 rounded font-medium">${r.category}</span></p>
                    </div>
                    <div class="flex items-center gap-3">
                        <span class="text-base font-bold text-slate-900">￥${parseFloat(r.amount).toFixed(2)}</span>
                        <button data-action="delete-record" data-id="${r.id}" class="text-slate-300 hover:text-red-500 font-medium text-xs">删除</button>
                    </div>
                </div>
            `).join('');
        } else {
            document.getElementById('totalSumTag').innerText = `￥0.00`;
            document.getElementById('totalCountTag').innerText = `0 笔`;
            container.innerHTML = '<p class="text-xs text-slate-400 text-center py-8">没有找到明细</p>';
        }
    } catch (err) {
        container.innerHTML = `<p class="text-xs text-red-500 text-center py-8">筛选失败: ${err.message}</p>`;
    }
}

async function handleRecordSubmit(event) {
    event.preventDefault();
    const btn = document.getElementById('saveBtn');
    btn.disabled = true; btn.innerText = '同步中...';

    try {
        await api.addRecord({
            user_id: state.currentUser.id,
            date: document.getElementById('dateInput').value,
            description: document.getElementById('descInput').value,
            amount: parseFloat(document.getElementById('amountInput').value),
            category: document.getElementById('categorySelect').value
        });

        document.getElementById('descInput').value = '';
        document.getElementById('amountInput').value = '';
        document.getElementById('matchTip').classList.add('invisible');
        fetchAndRenderRecords();
    } catch (err) {
        alert('记账保存失败：' + err.message);
    } finally {
        btn.disabled = false; btn.innerText = '保存记账记录';
    }
}

async function handleDeleteRecord(e) {
    if (e.target.dataset.action === 'delete-record') {
        if (!confirm('确定删除该笔账单记录吗？')) return;
        await api.deleteRecord(e.target.dataset.id);
        fetchAndRenderRecords();
    }
}