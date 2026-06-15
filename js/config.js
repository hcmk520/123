// 核心：引入 Supabase SDK (通过 CDN)
import 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2';

const MEMFIRE_URL = 'https://wfetefynqbzjugxluyoh.supabase.co'; 
const MEMFIRE_KEY = 'sb_publishable_TAYEJl2TPlFxNcjogICL2Q_2pdtn0Ek';

// 国内环境适配
export const supabase = window.supabase.createClient(MEMFIRE_URL, MEMFIRE_KEY, {
    auth: {
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: false
    }
});

// 默认智能分类匹配规则
export const smartRules = {
    '出差垫付': ['出差', '高铁', '机票', '酒店', '住宿', '打车', '出租车', '客运', '垫付', '拜访'],
    '必要花销': ['房租', '水电', '话费', '买菜', '大米', '油', '医疗', '药品', '体检', '地铁', '公交'],
    '社交花销': ['请客', '聚餐', '送礼', '份子钱', '聚会', '发红包', '酒吧', 'KTV', '电影'],
    '额外花销': ['奶茶', '咖啡', '零食', '游戏', '皮肤', '抽盲盒', '衣服', '鞋子', '网购', '玩具']
};