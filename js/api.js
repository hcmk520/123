import { supabase } from './config.js';

// --- 认证相关 ---
export async function registerUser(email, password, inviteKey) {
    // 校验邀请码
    const { data: isValidKey, error: rpcError } = await supabase.rpc('verify_and_use_invite_key', { invite_key: inviteKey });
    if (rpcError) throw new Error('解析邀请码错误: ' + rpcError.message);
    if (!isValidKey) throw new Error('邀请码无效、过期或已被他人使用！');

    // 注册
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) throw error;
    if (!data.user) throw new Error("注册响应异常，请检查配置。");

    // 初始化分类
    await supabase.from('user_categories').insert([
        { user_id: data.user.id, name: '必要花销', icon: '🛒' },
        { user_id: data.user.id, name: '额外花销', icon: '🎒' },
        { user_id: data.user.id, name: '出差垫付', icon: '💼' },
        { user_id: data.user.id, name: '社交花销', icon: '🤝' }
    ]);
    return data.user;
}

export async function loginUser(email, password) {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw error;
    return data.user;
}

export async function logoutUser() {
    await supabase.auth.signOut();
}

// --- 分类相关 ---
export async function getCategories() {
    const { data, error } = await supabase.from('user_categories').select('*').order('id', { ascending: true });
    if (error) throw error;
    return data;
}

export async function addCategory(userId, name) {
    const { error } = await supabase.from('user_categories').insert([{ user_id: userId, name, icon: '🏷️' }]);
    if (error) throw error;
}

export async function deleteCategory(id) {
    const { error } = await supabase.from('user_categories').delete().eq('id', id);
    if (error) throw error;
}

// --- 账单相关 ---
export async function getRecords(monthVal, selectedCatsArray) {
    let query = supabase.from('records').select('*');

    if (monthVal) {
        const startDate = `${monthVal}-01`;
        const year = parseInt(monthVal.split('-')[0]);
        const month = parseInt(monthVal.split('-')[1]);
        const endDate = new Date(year, month, 0).toISOString().split('T')[0];
        query = query.gte('date', startDate).lte('date', endDate);
    }

    if (selectedCatsArray.length > 0) {
        query = query.in('category', selectedCatsArray);
    }

    const { data, error } = await query.order('date', { ascending: false });
    if (error) throw error;
    return data;
}

export async function addRecord(recordData) {
    const { error } = await supabase.from('records').insert([recordData]);
    if (error) throw error;
}

export async function deleteRecord(id) {
    const { error } = await supabase.from('records').delete().eq('id', id);
    if (error) throw error;
}