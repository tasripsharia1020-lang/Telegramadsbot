
import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';
import { Telegraf, Markup } from 'telegraf';
import { createClient } from '@supabase/supabase-js';

const required = [
  'BOT_TOKEN',
  'ADMIN_ID',
  'APP_URL',
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY'
];

for (const key of required) {
  if (!process.env[key]) throw new Error(`Missing environment variable: ${key}`);
}

const cfg = {
  botToken: process.env.BOT_TOKEN,
  adminId: Number(process.env.ADMIN_ID),
  appUrl: process.env.APP_URL.replace(/\/$/, ''),
  targetChatId: process.env.TARGET_CHAT_ID || '@adseearn',
  targetChatUrl: process.env.TARGET_CHAT_URL || 'https://t.me/adseearn',
  minimumWithdrawal: 1000000,
  joinReward: 50000,
  referralRate: 10,
  port: Number(process.env.PORT || 3000)
};

const monetag = {
  zoneId: process.env.MONETAG_ZONE_ID || '12354877',
  secret: process.env.MONETAG_POSTBACK_SECRET || '',
  reward: 10,
  dailyLimit: 5,
  enabled: process.env.MONETAG_ENABLED === 'true'
};

const adsEnabled = monetag.enabled && Boolean(monetag.secret);

if (!Number.isSafeInteger(cfg.adminId) || cfg.adminId <= 0) {
  throw new Error('ADMIN_ID must be your numeric Telegram user ID');
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

const bot = new Telegraf(cfg.botToken);
const app = express();
let botUsername = '';

const allowedOrigins = new Set([
  'https://telegramadsbot.tasripsharia1030.workers.dev',
  'https://telegramadsbot-0oan.onrender.com'
]);

// CORS
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin) {
    if (!allowedOrigins.has(origin)) {
      return res.status(403).json({ error: 'Origin not allowed' });
    }
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Telegram-Init-Data');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.use(express.json({
  limit: '100kb',
  verify: (req, res, buffer) => { req.rawBody = buffer; }
}));

app.use(express.static('public'));

// Telegram Mini App authentication
function verifyTelegramInitData(initData) {
  if (!initData) return null;

  const params = new URLSearchParams(initData);
  const hash = params.get('hash');

  if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) return null;

  params.delete('hash');

  const authDate = Number(params.get('auth_date'));
  const now = Math.floor(Date.now() / 1000);

  if (!authDate || authDate > now + 60 || now - authDate > 3600) return null;

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');

  const secretKey = crypto
    .createHmac('sha256', 'WebAppData')
    .update(cfg.botToken)
    .digest();

  const calculatedHash = crypto
    .createHmac('sha256', secretKey)
    .update(dataCheckString)
    .digest('hex');

  const a = Buffer.from(calculatedHash, 'hex');
  const b = Buffer.from(hash, 'hex');

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  try {
    const user = JSON.parse(params.get('user') || '{}');
    return user.id ? user : null;
  } catch {
    return null;
  }
}

function requireMiniApp(req, res, next) {
  const user = verifyTelegramInitData(req.headers['x-telegram-init-data']);

  if (!user) return res.status(401).json({ error: 'Telegram authentication failed' });

  req.telegramUser = user;
  next();
}

function validBep20Address(address) {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

function isValidTelegramId(value) {
  return Number.isSafeInteger(Number(value)) && Number(value) > 0;
}

async function getAnvSetting(key, fallback = 0) {
  const { data, error } = await supabase
    .from('anv_settings')
    .select('setting_value')
    .eq('setting_key', key)
    .maybeSingle();

  if (error) throw error;
  if (!data) return fallback;

  const value = Number(data.setting_value);
  return Number.isFinite(value) ? value : fallback;
}

async function ensureAnvAccount(telegramId) {
  const { error } = await supabase
    .from('anv_accounts')
    .upsert(
      { telegram_id: telegramId },
      { onConflict: 'telegram_id', ignoreDuplicates: true }
    );

  if (error) throw error;
}

// User registration and ANV referral
async function saveUser(user, referralId = null) {
  const telegramId = Number(user.id);

  const { data: existing, error: existingError } = await supabase
    .from('users')
    .select('telegram_id, referred_by')
    .eq('telegram_id', telegramId)
    .maybeSingle();

  if (existingError) throw existingError;

  const validReferral =
    isValidTelegramId(referralId) && Number(referralId) !== telegramId;

  const row = {
    telegram_id: telegramId,
    username: user.username || null,
    first_name: user.first_name || null
  };

  if (!existing && validReferral) row.referred_by = Number(referralId);

  const { error: upsertError } = await supabase
    .from('users')
    .upsert(row, { onConflict: 'telegram_id', ignoreDuplicates: true });

  if (upsertError) throw upsertError;

  const { error: updateError } = await supabase
    .from('users')
    .update({
      username: user.username || null,
      first_name: user.first_name || null
    })
    .eq('telegram_id', telegramId);

  if (updateError) throw updateError;

  let finalReferrer = existing?.referred_by || null;

  if (!finalReferrer && validReferral) {
    const { data: updatedReferral, error: referralError } = await supabase
      .from('users')
      .update({ referred_by: Number(referralId) })
      .eq('telegram_id', telegramId)
      .is('referred_by', null)
      .select('referred_by')
      .maybeSingle();

    if (referralError) throw referralError;

    if (updatedReferral?.referred_by) {
      finalReferrer = updatedReferral.referred_by;
    } else if (!existing) {
      finalReferrer = Number(referralId);
    }
  }

  await ensureAnvAccount(telegramId);

  if (
    finalReferrer &&
    isValidTelegramId(finalReferrer) &&
    Number(finalReferrer) !== telegramId
  ) {
    const { error } = await supabase.rpc('anv_credit_referral', {
      p_referrer_id: Number(finalReferrer),
      p_referred_id: telegramId
    });

    if (error) console.error('ANV referral credit error:', error);
  }
}

const adProviders = [
  { id: 'monetag', enabled: adsEnabled, configured: Boolean(monetag.secret) },
  { id: 'adsterra', enabled: false, configured: false },
  { id: 'propellerads', enabled: false, configured: false },
  { id: 'ad-maven', enabled: false, configured: false },
  { id: 'hilltopads', enabled: false, configured: false }
];

// Monetag session
app.post('/api/monetag/session', requireMiniApp, async (req, res) => {
  try {
    if (!adsEnabled) {
      return res.status(503).json({ error: 'Rewarded ads are currently disabled.' });
    }

    const telegramId = Number(req.telegramUser.id);
    const ymid = `anv_${crypto.randomBytes(24).toString('hex')}`;
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    const { error } = await supabase.from('monetag_ad_sessions').insert({
      ymid,
      telegram_id: telegramId,
      zone_id: monetag.zoneId,
      expires_at: expiresAt
    });

    if (error) throw error;

    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, ymid, expires_at: expiresAt });
  } catch (error) {
    console.error('Monetag session creation error:', error);
    return res.status(500).json({ error: 'Could not prepare a secure ad session.' });
  }
});

// Monetag verified postback
app.get('/api/monetag/postback', async (req, res) => {
  try {
    if (!monetag.secret) return res.status(503).send('Postback not configured');

    const supplied = Buffer.from(String(req.query.secret || ''));
    const expected = Buffer.from(monetag.secret);

    if (
      supplied.length !== expected.length ||
      !crypto.timingSafeEqual(supplied, expected)
    ) return res.sendStatus(401);

    const {
      ymid, zone_id, sub_zone_id, event_type,
      reward_event_type, estimated_price
    } = req.query;

    if (
      String(zone_id || '') !== monetag.zoneId ||
      String(event_type || '') !== 'impression' ||
      String(reward_event_type || '') !== 'valued' ||
      !/^anv_[a-f0-9]{48}$/.test(String(ymid || ''))
    ) return res.status(200).send('IGNORED');

    const price = Number(estimated_price || 0);
    if (!Number.isFinite(price) || price < 0) {
      return res.status(200).send('INVALID_PRICE');
    }

    const { data: session, error: sessionError } = await supabase
      .from('monetag_ad_sessions')
      .select('telegram_id')
      .eq('ymid', String(ymid))
      .eq('zone_id', monetag.zoneId)
      .gt('expires_at', new Date().toISOString())
      .is('consumed_at', null)
      .maybeSingle();

    if (sessionError) {
      console.error('Monetag session lookup error:', sessionError);
      return res.sendStatus(500);
    }

    if (!session?.telegram_id) return res.status(200).send('INVALID_SESSION');

    const { data, error } = await supabase.rpc('anv_credit_monetag_reward', {
      p_ymid: String(ymid),
      p_telegram_id: Number(session.telegram_id),
      p_zone_id: String(zone_id),
      p_sub_zone_id: String(sub_zone_id || ''),
      p_event_type: String(event_type),
      p_reward_event_type: String(reward_event_type),
      p_estimated_price: price
    });

    if (error) {
      console.error('Monetag reward RPC error:', error);
      return res.sendStatus(500);
    }

    if (!data || data.ok !== true) {
      return res.status(200).send(
        data?.reason === 'duplicate' ? 'DUPLICATE' :
        data?.reason === 'daily_limit' ? 'DAILY_LIMIT' :
        'REWARD_NOT_CREDITED'
      );
    }

    console.log('MONETAG REWARD CREDITED:', {
      telegram_id: session.telegram_id,
      reward: data.reward,
      event_id: data.event_id
    });

    return res.status(200).send('OK');
  } catch (error) {
    console.error('Monetag postback error:', error);
    return res.sendStatus(500);
  }
});

// Health
app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'ANV Verse API' });
});

// App configuration
app.get('/api/config', async (req, res) => {
  try {
    const [miningReward, miningHours, dailyReward, referralReward] = await Promise.all([
      getAnvSetting('mining_reward', 0),
      getAnvSetting('mining_cycle_hours', 24),
      getAnvSetting('daily_checkin_reward', 0),
      getAnvSetting('referral_reward', 0)
    ]);

    res.set('Cache-Control', 'no-store');
    res.json({
      app_name: 'ANV Verse',
      coin_name: 'ANV Coin',
      minimum_withdrawal: cfg.minimumWithdrawal,
      join_reward: cfg.joinReward,
      group_url: cfg.targetChatUrl,
      bot_username: botUsername,
      referral_rate: cfg.referralRate,
      withdrawal_method: 'USDT (BNB Smart Chain BEP20)',
      ads_enabled: adsEnabled,
      ad_networks: adProviders,
      anv_enabled: true,
      anv_mining_reward: miningReward,
      anv_mining_cycle_hours: miningHours,
      anv_daily_checkin_reward: dailyReward,
      anv_referral_reward: referralReward,
      anv_withdraw_enabled: false,
      anv_swap_enabled: false
    });
  } catch (error) {
    console.error('Config error:', error);
    res.status(500).json({ error: 'Could not load configuration' });
  }
});

// Ads status
app.get('/api/ads/status', requireMiniApp, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');

    if (!adsEnabled) {
      return res.json({
        enabled: false, watched: 0,
        daily_limit: monetag.dailyLimit, remaining: 0,
        next_reset_at: null, earned_24h: 0,
        message: 'Ads are currently unavailable.'
      });
    }

    const now = new Date();
    const dayStart = new Date(Date.UTC(
      now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()
    ));
    const dayEnd = new Date(dayStart.getTime() + 86400000);

    const { count, error } = await supabase
      .from('monetag_reward_events')
      .select('id', { count: 'exact', head: true })
      .eq('telegram_id', req.telegramUser.id)
      .gte('created_at', dayStart.toISOString())
      .lt('created_at', dayEnd.toISOString());

    if (error) throw error;

    const watched = Number(count || 0);
    const remaining = Math.max(0, monetag.dailyLimit - watched);

    return res.json({
      enabled: remaining > 0,
      watched,
      daily_limit: monetag.dailyLimit,
      remaining,
      next_reset_at: dayEnd.toISOString(),
      earned_24h: watched * monetag.reward,
      message: remaining > 0
        ? 'Rewarded ads are available.'
        : 'Daily rewarded ad limit reached.'
    });
  } catch (error) {
    console.error('Ad status error:', error);
    res.status(500).json({ error: 'Could not load ad status' });
  }
});

app.all('/api/ad-webhook', (req, res) => {
  res.status(503).json({
    error: 'Ad rewards are disabled. No provider callback is active.'
  });
});

// Authentication
app.post('/api/auth', requireMiniApp, async (req, res) => {
  try {
    await saveUser(req.telegramUser);
    res.json({
      ok: true,
      user: {
        id: req.telegramUser.id,
        first_name: req.telegramUser.first_name || ''
      }
    });
  } catch (error) {
    console.error('Auth error:', error);
    res.status(500).json({ error: 'Could not save user' });
  }
});

// Legacy USDT account
app.get('/api/me', requireMiniApp, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('telegram_id, username, first_name, balance, total_earned, created_at')
      .eq('telegram_id', req.telegramUser.id)
      .maybeSingle();

    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'User not found' });

    res.set('Cache-Control', 'no-store');
    res.json({ user: data });
  } catch (error) {
    console.error('Account error:', error);
    res.status(500).json({ error: 'Could not load account' });
  }
});

// ANV account and authoritative active mining session
app.get('/api/anv/me', requireMiniApp, async (req, res) => {
  try {
    const telegramId = Number(req.telegramUser.id);
    await ensureAnvAccount(telegramId);

    const [
      accountResult, sessionResult,
      miningReward, miningHours, dailyReward, referralReward
    ] = await Promise.all([
      supabase.from('anv_accounts')
        .select('telegram_id, balance, total_earned, mining_level, created_at')
        .eq('telegram_id', telegramId)
        .maybeSingle(),

      supabase.from('anv_mining_sessions')
        .select('id, reward, started_at, ends_at, status')
        .eq('telegram_id', telegramId)
        .eq('status', 'active')
        .order('started_at', { ascending: false })
        .limit(1)
        .maybeSingle(),

      getAnvSetting('mining_reward', 0),
      getAnvSetting('mining_cycle_hours', 24),
      getAnvSetting('daily_checkin_reward', 0),
      getAnvSetting('referral_reward', 0)
    ]);

    if (accountResult.error) throw accountResult.error;
    if (sessionResult.error) throw sessionResult.error;

    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.set('Pragma', 'no-cache');

    return res.json({
      ok: true,
      server_time: new Date().toISOString(),
      account: accountResult.data || {
        telegram_id: telegramId,
        balance: 0,
        total_earned: 0,
        mining_level: 1
      },
      mining: sessionResult.data || null,
      settings: {
        mining_reward: miningReward,
        mining_cycle_hours: miningHours,
        daily_checkin_reward: dailyReward,
        referral_reward: referralReward,
        withdraw_enabled: false,
        swap_enabled: false
      }
    });
  } catch (error) {
    console.error('ANV account error:', error);
    res.status(500).json({ error: 'Could not load ANV account' });
  }
});

// Mining start: return existing session if one is already active.
// Never create a frontend-only countdown.
app.post('/api/anv/mining/start', requireMiniApp, async (req, res) => {
  try {
    const telegramId = Number(req.telegramUser.id);
    await ensureAnvAccount(telegramId);

    const { data, error } = await supabase.rpc('anv_start_mining', {
      p_telegram_id: telegramId
    });

    if (error) throw error;

    const { data: activeSession, error: sessionError } = await supabase
      .from('anv_mining_sessions')
      .select('id, reward, started_at, ends_at, status')
      .eq('telegram_id', telegramId)
      .eq('status', 'active')
      .order('started_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (sessionError) throw sessionError;

    if (activeSession) {
      res.set('Cache-Control', 'no-store');
      return res.json({
        ok: true,
        existing: data?.reason === 'already_active',
        mining: activeSession
      });
    }

    if (!data || data.ok !== true) {
      const reason = data?.reason || 'could_not_start';
      const messages = {
        reward_not_configured: 'Mining reward has not been configured yet.',
        already_active: 'Your active mining session could not be loaded.'
      };

      return res.status(409).json({
        ok: false,
        reason,
        error: messages[reason] || 'Could not start mining.',
        ends_at: data?.ends_at || null
      });
    }

    return res.status(500).json({
      ok: false,
      error: 'Mining started but the active session could not be retrieved.'
    });
  } catch (error) {
    console.error('ANV mining start error:', error);
    res.status(500).json({ ok: false, error: 'Could not start mining' });
  }
});

// Mining collect
app.post('/api/anv/mining/collect', requireMiniApp, async (req, res) => {
  try {
    const telegramId = Number(req.telegramUser.id);

    const { data, error } = await supabase.rpc('anv_collect_mining', {
      p_telegram_id: telegramId
    });

    if (error) throw error;

    if (!data || data.ok !== true) {
      const reason = data?.reason || 'not_ready';
      const messages = {
        no_active_mining: 'There is no active mining session.',
        no_active_session: 'There is no active mining session.',
        not_finished: 'Mining is not finished yet.',
        not_ready: 'Mining is not finished yet.'
      };

      res.set('Cache-Control', 'no-store');
      return res.status(409).json({
        ok: false,
        reason,
        error: messages[reason] || 'Could not collect mining reward.',
        ends_at: data?.ends_at || null
      });
    }

    res.set('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      reward: data.reward,
      account: data.account || null
    });
  } catch (error) {
    console.error('ANV mining collect error:', error);
    res.status(500).json({ ok: false, error: 'Could not collect mining reward' });
  }
});

// Daily check-in status
app.get('/api/anv/daily/status', requireMiniApp, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);

    const { data, error } = await supabase
      .from('anv_task_claims')
      .select('id, task_id, claim_date, reward')
      .eq('telegram_id', req.telegramUser.id)
      .eq('task_id', 'daily_checkin')
      .eq('claim_date', today)
      .maybeSingle();

    if (error) throw error;

    res.set('Cache-Control', 'no-store');
    res.json({
      claimed: Boolean(data),
      task_id: 'daily_checkin',
      claim_date: today,
      reward: data?.reward || 0
    });
  } catch (error) {
    console.error('ANV daily status error:', error);
    res.status(500).json({ error: 'Could not load daily check-in status' });
  }
});

// Daily check-in claim
app.post('/api/anv/daily/claim', requireMiniApp, async (req, res) => {
  try {
    await ensureAnvAccount(req.telegramUser.id);

    const { data, error } = await supabase.rpc('anv_claim_daily', {
      p_telegram_id: req.telegramUser.id
    });

    if (error) throw error;

    if (!data || data.ok !== true) {
      const reason = data?.reason || 'could_not_claim';
      const messages = {
        reward_not_configured: 'Daily check-in reward is not configured yet.',
        already_claimed: 'You have already claimed today’s check-in reward.'
      };

      return res.status(409).json({
        ok: false,
        reason,
        error: messages[reason] || 'Could not claim daily reward.'
      });
    }

    res.json({ ok: true, reward: data.reward });
  } catch (error) {
    console.error('ANV daily claim error:', error);
    res.status(500).json({ error: 'Could not claim daily reward' });
  }
});

// ANV transaction history
app.get('/api/anv/history', requireMiniApp, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('anv_transactions')
      .select('id, amount, transaction_type, source, description, created_at')
      .eq('telegram_id', req.telegramUser.id)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) throw error;

    res.set('Cache-Control', 'no-store');
    res.json({ transactions: data || [] });
  } catch (error) {
    console.error('ANV history error:', error);
    res.status(500).json({ error: 'Could not load ANV history' });
  }
});

// ANV referrals
app.get('/api/anv/referrals', requireMiniApp, async (req, res) => {
  try {
    const telegramId = Number(req.telegramUser.id);

    const [usersResult, rewardsResult, referralReward] = await Promise.all([
      supabase.from('users')
        .select('telegram_id, username, first_name, created_at')
        .eq('referred_by', telegramId)
        .order('created_at', { ascending: false })
        .limit(500),

      supabase.from('anv_transactions')
        .select('amount')
        .eq('telegram_id', telegramId)
        .eq('source', 'referral')
        .eq('transaction_type', 'credit')
        .limit(10000),

      getAnvSetting('referral_reward', 0)
    ]);

    if (usersResult.error) throw usersResult.error;
    if (rewardsResult.error) throw rewardsResult.error;

    const totalRewards = (rewardsResult.data || []).reduce(
      (sum, item) => sum + Number(item.amount || 0), 0
    );

    const referrals = (usersResult.data || []).map(user => ({
      telegram_id: user.telegram_id,
      username: user.username,
      first_name: user.first_name,
      joined_at: user.created_at
    }));

    res.set('Cache-Control', 'no-store');
    res.json({
      total_referrals: referrals.length,
      anv_earned: totalRewards,
      reward_per_referral: referralReward,
      referral_link: botUsername
        ? `https://t.me/${botUsername}?start=ref_${telegramId}`
        : null,
      referrals
    });
  } catch (error) {
    console.error('ANV referral error:', error);
    res.status(500).json({ error: 'Could not load ANV referral statistics' });
  }
});

// Group join task status
app.get('/api/tasks/status', requireMiniApp, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('join_tasks')
      .select('task_id')
      .eq('telegram_id', req.telegramUser.id)
      .eq('task_id', 'main_channel')
      .maybeSingle();

    if (error) throw error;

    res.set('Cache-Control', 'no-store');
    res.json({ claimed: Boolean(data), task_id: 'main_channel' });
  } catch (error) {
    console.error('Task status error:', error);
    res.status(500).json({ error: 'Could not load task status' });
  }
});

// Legacy USDT referrals
app.get('/api/referrals', requireMiniApp, async (req, res) => {
  try {
    const telegramId = Number(req.telegramUser.id);

    const { data: referredUsers, error: usersError } = await supabase
      .from('users')
      .select('telegram_id, username, first_name, created_at')
      .eq('referred_by', telegramId)
      .order('created_at', { ascending: false })
      .limit(500);

    if (usersError) throw usersError;

    const { data: commissions, error: commissionError } = await supabase
      .from('referral_commission_events')
      .select('referred_telegram_id, amount')
      .eq('referrer_telegram_id', telegramId)
      .limit(10000);

    if (commissionError) throw commissionError;

    const commissionMap = new Map();
    for (const item of commissions || []) {
      const id = String(item.referred_telegram_id);
      commissionMap.set(id, (commissionMap.get(id) || 0) + Number(item.amount || 0));
    }

    const totalCommission = (commissions || []).reduce(
      (sum, item) => sum + Number(item.amount || 0), 0
    );

    const referrals = (referredUsers || []).map(user => ({
      telegram_id: user.telegram_id,
      username: user.username,
      first_name: user.first_name,
      joined_at: user.created_at,
      commission: commissionMap.get(String(user.telegram_id)) || 0
    }));

    res.set('Cache-Control', 'no-store');
    res.json({
      total_referrals: referrals.length,
      referral_earnings: totalCommission,
      referral_rate: cfg.referralRate,
      referral_link: botUsername
        ? `https://t.me/${botUsername}?start=ref_${telegramId}`
        : null,
      referrals
    });
  } catch (error) {
    console.error('Referral error:', error);
    res.status(500).json({ error: 'Could not load referral statistics' });
  }
});

// Verify Telegram group membership and claim existing one-time USDT reward
app.post('/api/tasks/join', requireMiniApp, async (req, res) => {
  try {
    const member = await bot.telegram.getChatMember(
      cfg.targetChatId,
      req.telegramUser.id
    );

    if (!['member', 'administrator', 'creator'].includes(member.status)) {
      return res.status(403).json({ error: 'Join the required channel first' });
    }

    const { data, error } = await supabase.rpc('complete_join_task', {
      p_telegram_id: req.telegramUser.id,
      p_task_id: 'main_channel',
      p_reward: cfg.joinReward
    });

    if (error) throw error;

    if (!data || data.ok !== true) {
      return res.status(409).json({
        error: 'Task already completed',
        claimed: true
      });
    }

    res.json({
      ok: true,
      claimed: true,
      reward: cfg.joinReward,
      reward_usdt: '0.05'
    });
  } catch (error) {
    console.error('Join task error:', error);
    res.status(500).json({ error: 'Could not verify membership. Please try again.' });
  }
});

// USDT withdrawal
app.post('/api/withdraw', requireMiniApp, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const method = String(req.body.method || '')
      .trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    const details = String(req.body.details || '').trim();

    if (!Number.isSafeInteger(amount) || amount < cfg.minimumWithdrawal) {
      return res.status(400).json({ error: 'Minimum withdrawal is $1 USDT.' });
    }

    if (!method.includes('USDT') || !method.includes('BEP20')) {
      return res.status(400).json({
        error: 'Only USDT on BNB Smart Chain (BEP20) is supported.'
      });
    }

    if (!validBep20Address(details)) {
      return res.status(400).json({
        error: 'Enter a valid 42-character BNB Smart Chain address.'
      });
    }

    const { data, error } = await supabase.rpc('create_withdrawal', {
      p_telegram_id: req.telegramUser.id,
      p_amount: amount,
      p_method: 'USDT (BNB Smart Chain BEP20)',
      p_details: details,
      p_minimum: cfg.minimumWithdrawal
    });

    if (error) throw error;

    if (!data || !data.ok) {
      const messages = {
        invalid: 'Invalid withdrawal details.',
        pending: 'You already have a pending withdrawal.',
        balance: 'Insufficient balance.'
      };
      return res.status(400).json({
        error: messages[data?.reason] || 'Withdrawal could not be created.'
      });
    }

    const user = req.telegramUser;
    const amountUsdt = (amount / 1000000).toFixed(2);
    const adminMessage =
      `🔔 NEW WITHDRAWAL REQUEST\n\n` +
      `👤 User: ${user.first_name || 'User'}\n` +
      `🆔 Telegram ID: ${user.id}\n` +
      `💰 Amount: $${amountUsdt} USDT\n` +
      `🌐 Network: BNB Smart Chain (BEP20)\n` +
      `💳 Wallet Address:\n${details}\n\n` +
      `📌 Status: PENDING\n🧾 Request ID:\n${data.id}`;

    let adminNotified = false;

    try {
      await bot.telegram.sendMessage(
        cfg.adminId,
        adminMessage,
        Markup.inlineKeyboard([[
          Markup.button.callback('✅ Approve', `wd_approve_${data.id}`),
          Markup.button.callback('❌ Reject + Refund', `wd_reject_${data.id}`)
        ]])
      );
      adminNotified = true;
    } catch (notifyError) {
      console.error('Admin notification failed:', notifyError);
    }

    res.json({
      ok: true,
      withdrawal_id: data.id,
      admin_notified: adminNotified
    });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ error: 'Could not create withdrawal' });
  }
});

// Withdrawal history
app.get('/api/withdrawals', requireMiniApp, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('withdrawals')
      .select('id, amount, payment_method, status, created_at, processed_at')
      .eq('telegram_id', req.telegramUser.id)
      .order('created_at', { ascending: false })
      .limit(30);

    if (error) throw error;

    res.set('Cache-Control', 'no-store');
    res.json({ withdrawals: data || [] });
  } catch (error) {
    console.error('Withdrawal history error:', error);
    res.status(500).json({ error: 'Could not load withdrawals' });
  }
});

// Telegram bot
bot.start(async (ctx) => {
  try {
    const payload = ctx.startPayload || '';
    const refMatch = payload.match(/^ref_(\d+)$/);
    const referralId = refMatch ? Number(refMatch[1]) : null;

    await saveUser(ctx.from, referralId);

    await ctx.reply(
      `Welcome ${ctx.from.first_name || 'friend'}!\n\n` +
      'Open ANV Verse to view your ANV Coin balance, mining, tasks and profile.',
      Markup.inlineKeyboard([[
        Markup.button.webApp('🚀 Open ANV Verse', cfg.appUrl)
      ]])
    );
  } catch (error) {
    console.error('Start error:', error);
    await ctx.reply('Sorry, setup failed. Please try again later.');
  }
});

bot.command('id', (ctx) => ctx.reply(`Your Telegram ID: ${ctx.from.id}`));

bot.command('menu', (ctx) => {
  ctx.reply('Open ANV Verse:', Markup.inlineKeyboard([[
    Markup.button.webApp('🚀 Open ANV Verse', cfg.appUrl)
  ]]));
});

// Admin pending withdrawal list
bot.command('withdrawals', async (ctx) => {
  if (ctx.from.id !== cfg.adminId) return ctx.reply('Not authorized.');

  const { data, error } = await supabase
    .from('withdrawals')
    .select('id, telegram_id, amount, payment_method, payment_details, status')
    .eq('status', 'pending')
    .order('created_at', { ascending: true })
    .limit(10);

  if (error) {
    console.error(error);
    return ctx.reply('Could not load withdrawals.');
  }

  if (!data.length) return ctx.reply('No pending withdrawals.');

  for (const item of data) {
    await ctx.reply(
      `🔔 WITHDRAWAL REQUEST\n\n` +
      `🧾 ID: ${item.id}\n👤 User ID: ${item.telegram_id}\n` +
      `💰 Amount: $${(Number(item.amount) / 1000000).toFixed(2)} USDT\n` +
      `🌐 Network: ${item.payment_method}\n💳 Wallet:\n${item.payment_details}\n` +
      `📌 Status: ${item.status.toUpperCase()}`,
      Markup.inlineKeyboard([[
        Markup.button.callback('✅ Approve', `wd_approve_${item.id}`),
        Markup.button.callback('❌ Reject + Refund', `wd_reject_${item.id}`)
      ]])
    );
  }
});

// Admin approve/reject
bot.action(/^wd_(approve|reject)_([0-9a-f-]+)$/i, async (ctx) => {
  if (ctx.from.id !== cfg.adminId) {
    return ctx.answerCbQuery('Not authorized', { show_alert: true });
  }

  try {
    const approve = ctx.match[1] === 'approve';
    const id = ctx.match[2];

    const { data, error } = await supabase.rpc('process_withdrawal', {
      p_id: id,
      p_admin: cfg.adminId,
      p_approve: approve,
      p_authorized_admin: cfg.adminId
    });

    if (error) throw error;
    if (!data || !data.ok) return ctx.answerCbQuery(data?.reason || 'Could not process');

    await ctx.editMessageText(
      `Withdrawal ${approve ? 'approved' : 'rejected and refunded'}.\nID: ${id}`
    );
    await ctx.answerCbQuery('Done');
  } catch (error) {
    console.error('Admin action error:', error);
    await ctx.answerCbQuery('Action failed', { show_alert: true });
  }
});

bot.catch((error) => console.error('Telegram bot error:', error));

// Start server and bot
const server = app.listen(cfg.port, () => {
  console.log(`Server listening on port ${cfg.port}`);
});

(async () => {
  try {
    const me = await bot.telegram.getMe();
    botUsername = me.username || '';
    await bot.launch();
    console.log(`Telegram bot started${botUsername ? ` as @${botUsername}` : ''}`);
  } catch (error) {
    console.error('Telegram bot launch failed:', error);
    process.exit(1);
  }
})();

process.once('SIGINT', () => {
  bot.stop('SIGINT');
  server.close();
});

process.once('SIGTERM', () => {
  bot.stop('SIGTERM');
  server.close();
});
