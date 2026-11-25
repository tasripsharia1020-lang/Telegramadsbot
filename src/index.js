
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
  if (!process.env[key]) {
    throw new Error(`Missing environment variable: ${key}`);
  }
}

const cfg = {
  botToken: process.env.BOT_TOKEN,
  adminId: Number(process.env.ADMIN_ID),
  appUrl: process.env.APP_URL.replace(/\/$/, ''),
  targetChatId: process.env.TARGET_CHAT_ID || '@adseearn',
  targetChatUrl: process.env.TARGET_CHAT_URL || 'https://t.me/adseearn',
  dailyLimit: 500,
  adReward: 5000,
  adsgramBlockId: process.env.ADSGRAM_BLOCK_ID || '61753',
  adsgramRewardSecret: process.env.ADSGRAM_REWARD_SECRET || '',
  minimumWithdrawal: 1000000,
  joinReward: 50000,
  referralRate: 10,
  adSecret: process.env.AD_PROVIDER_WEBHOOK_SECRET || '',
  port: Number(process.env.PORT || 3000)
};

if (!Number.isSafeInteger(cfg.adminId) || cfg.adminId <= 0) {
  throw new Error('ADMIN_ID must be your numeric Telegram user ID');
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

const bot = new Telegraf(cfg.botToken);
let botUsername = '';
const app = express();

app.use(express.json({
  verify: (req, res, buffer) => {
    req.rawBody = buffer;
  }
}));

app.use(express.static('public'));

function verifyTelegramInitData(initData) {
  if (!initData) return null;

  const params = new URLSearchParams(initData);
  const hash = params.get('hash');

  if (!hash) return null;

  params.delete('hash');

  const authDate = Number(params.get('auth_date'));
  const now = Math.floor(Date.now() / 1000);

  if (
    !authDate ||
    authDate > now + 60 ||
    now - authDate > 3600
  ) {
    return null;
  }

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

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return null;
  }

  try {
    const user = JSON.parse(params.get('user') || '{}');

    if (!user.id) return null;

    return user;
  } catch {
    return null;
  }
}

async function saveUser(user, referralId = null) {
  const row = {
    telegram_id: user.id,
    username: user.username || null,
    first_name: user.first_name || null
  };

  if (
    referralId &&
    Number(referralId) !== Number(user.id)
  ) {
    row.referred_by = referralId;
  }

  const { error } = await supabase
    .from('users')
    .upsert(row, {
      onConflict: 'telegram_id',
      ignoreDuplicates: true
    });

  if (error) throw error;

  const { error: updateError } = await supabase
    .from('users')
    .update({
      username: user.username || null,
      first_name: user.first_name || null
    })
    .eq('telegram_id', user.id);

  if (updateError) throw updateError;
}

function requireMiniApp(req, res, next) {
  const user = verifyTelegramInitData(
    req.headers['x-telegram-init-data']
  );

  if (!user) {
    return res.status(401).json({
      error: 'Telegram authentication failed'
    });
  }

  req.telegramUser = user;
  next();
}

function validBep20Address(address) {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: 'Telegramadsbot'
  });
});

app.get('/api/config', (req, res) => {
  res.set('Cache-Control', 'no-store');

  res.json({
    daily_limit: cfg.dailyLimit,
    minimum_withdrawal: cfg.minimumWithdrawal,
    ad_reward: cfg.adReward,
    join_reward: cfg.joinReward,
    group_url: cfg.targetChatUrl,
    adsgram_block_id: cfg.adsgramBlockId,
    bot_username: botUsername,
    referral_rate: cfg.referralRate,
    withdrawal_method: 'USDT (BNB Smart Chain BEP20)'
  });
});

// AdsGram reward callback
app.get('/api/adsgram/reward', async (req, res) => {
  try {
    const supplied = Buffer.from(
      String(req.query.secret || '')
    );

    const expected = Buffer.from(
      cfg.adsgramRewardSecret
    );

    if (
      !expected.length ||
      supplied.length !== expected.length ||
      !crypto.timingSafeEqual(supplied, expected)
    ) {
      return res.status(401).send('Unauthorized');
    }

    const telegramId = String(
      req.query.userid || req.query.userId || ''
    );

    if (!/^\d{1,20}$/.test(telegramId)) {
      return res.status(400).send('Invalid user');
    }

    const { data, error } = await supabase.rpc(
      'credit_adsgram_reward',
      {
        p_telegram_id: telegramId,
        p_reward: cfg.adReward,
        p_daily_limit: cfg.dailyLimit
      }
    );

    if (error) throw error;

    if (!data || data.ok !== true) {
      return res.status(409).send(
        data?.reason || 'Reward not credited'
      );
    }

    return res.status(200).send('OK');

  } catch (error) {
    console.error('AdsGram reward callback error:', error);
    return res.status(500).send('Reward processing failed');
  }
});

app.get('/api/ads/status', requireMiniApp, async (req, res) => {
  try {
    const { data, error } = await supabase.rpc(
      'get_adsgram_status',
      {
        p_telegram_id: String(req.telegramUser.id),
        p_daily_limit: cfg.dailyLimit
      }
    );

    if (error) throw error;

    const watched = Number(data?.watched || 0);

    res.json({
      watched,
      daily_limit: cfg.dailyLimit,
      remaining: Math.max(0, cfg.dailyLimit - watched),
      next_reset_at: data?.next_reset_at || null,
      earned_24h: Number(data?.earned_24h || 0)
    });

  } catch (error) {
    console.error('Ads status error:', error);
    res.status(503).json({
      error: 'Ads reward SQL setup is required'
    });
  }
});

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
    res.status(500).json({
      error: 'Could not save user'
    });
  }
});

app.get('/api/me', requireMiniApp, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select(
      'telegram_id, username, first_name, balance, total_earned, created_at'
    )
    .eq('telegram_id', req.telegramUser.id)
    .maybeSingle();

  if (error) {
    console.error(error);
    return res.status(500).json({
      error: 'Could not load account'
    });
  }

  if (!data) {
    return res.status(404).json({
      error: 'User not found'
    });
  }

  res.json({ user: data });
});

// Referral statistics and referred user list
app.get('/api/referrals', requireMiniApp, async (req, res) => {
  try {
    const telegramId = req.telegramUser.id;

    const { data: referredUsers, error: usersError } =
      await supabase
        .from('users')
        .select('telegram_id, username, first_name, created_at')
        .eq('referred_by', telegramId)
        .order('created_at', { ascending: false })
        .limit(500);

    if (usersError) throw usersError;

    const { data: commissions, error: commissionError } =
      await supabase
        .from('referral_commission_events')
        .select(
          'referred_telegram_id, amount'
        )
        .eq('referrer_telegram_id', telegramId)
        .limit(10000);

    if (commissionError) throw commissionError;

    const commissionMap = new Map();

    for (const item of commissions || []) {
      const id = String(item.referred_telegram_id);
      const previous = commissionMap.get(id) || 0;

      commissionMap.set(
        id,
        previous + Number(item.amount || 0)
      );
    }

    const totalCommission = (commissions || [])
      .reduce(
        (sum, item) => sum + Number(item.amount || 0),
        0
      );

    const referrals = (referredUsers || []).map(user => ({
      telegram_id: user.telegram_id,
      username: user.username,
      first_name: user.first_name,
      joined_at: user.created_at,
      commission: commissionMap.get(
        String(user.telegram_id)
      ) || 0
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
    res.status(500).json({
      error: 'Could not load referral statistics'
    });
  }
});

app.post('/api/tasks/join', requireMiniApp, async (req, res) => {
  try {
    if (!cfg.targetChatId) {
      return res.status(503).json({
        error: 'Join task is not configured'
      });
    }

    const member = await bot.telegram.getChatMember(
      cfg.targetChatId,
      req.telegramUser.id
    );

    const allowed = [
      'member',
      'administrator',
      'creator'
    ];

    if (!allowed.includes(member.status)) {
      return res.status(403).json({
        error: 'Join the required channel first'
      });
    }

    const { data, error } = await supabase.rpc(
      'complete_join_task',
      {
        p_telegram_id: req.telegramUser.id,
        p_task_id: 'main_channel',
        p_reward: cfg.joinReward
      }
    );

    if (error) throw error;

    if (!data.ok) {
      return res.status(409).json({
        error: 'Task already completed'
      });
    }

    res.json({
      ok: true,
      reward: cfg.joinReward,
      reward_usdt: '0.05'
    });

  } catch (error) {
    console.error('Join task error:', error);
    res.status(500).json({
      error: 'Could not verify membership'
    });
  }
});

// USDT BEP20 withdrawal
app.post('/api/withdraw', requireMiniApp, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const method = String(req.body.method || '')
      .trim()
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, '');

    const details = String(req.body.details || '').trim();

    if (
      !Number.isSafeInteger(amount) ||
      amount < cfg.minimumWithdrawal
    ) {
      return res.status(400).json({
        error: 'Minimum withdrawal is $1 USDT.'
      });
    }

    if (
      !method.includes('USDT') ||
      !method.includes('BEP20')
    ) {
      return res.status(400).json({
        error: 'Only USDT on BNB Smart Chain (BEP20) is supported.'
      });
    }

    if (!validBep20Address(details)) {
      return res.status(400).json({
        error: 'Enter a valid 42-character BNB Smart Chain address.'
      });
    }

    const { data, error } = await supabase.rpc(
      'create_withdrawal',
      {
        p_telegram_id: req.telegramUser.id,
        p_amount: amount,
        p_method: 'USDT (BNB Smart Chain BEP20)',
        p_details: details,
        p_minimum: cfg.minimumWithdrawal
      }
    );

    if (error) throw error;

    if (!data || !data.ok) {
      const messages = {
        invalid: 'Invalid withdrawal details.',
        pending: 'You already have a pending withdrawal.',
        balance: 'Insufficient balance.'
      };

      return res.status(400).json({
        error: messages[data?.reason] ||
          'Withdrawal could not be created.'
      });
    }

    res.json({
      ok: true,
      withdrawal_id: data.id
    });

  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({
      error: 'Could not create withdrawal'
    });
  }
});

app.get('/api/withdrawals', requireMiniApp, async (req, res) => {
  const { data, error } = await supabase
    .from('withdrawals')
    .select(
      'id, amount, payment_method, status, created_at, processed_at'
    )
    .eq('telegram_id', req.telegramUser.id)
    .order('created_at', { ascending: false })
    .limit(30);

  if (error) {
    console.error(error);
    return res.status(500).json({
      error: 'Could not load withdrawals'
    });
  }

  res.json({
    withdrawals: data || []
  });
});

// Disabled generic webhook
app.post('/api/ad-webhook', async (req, res) => {
  if (
    process.env.AD_PROVIDER !== 'enabled' ||
    !cfg.adSecret
  ) {
    return res.status(503).json({
      error: 'Ad rewards are disabled'
    });
  }

  const signature = req.headers['x-ad-signature'];

  const expected = crypto
    .createHmac('sha256', cfg.adSecret)
    .update(req.rawBody || Buffer.alloc(0))
    .digest('hex');

  if (
    typeof signature !== 'string' ||
    !/^[a-f0-9]{64}$/i.test(signature) ||
    !crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expected, 'hex')
    )
  ) {
    return res.status(401).json({
      error: 'Invalid signature'
    });
  }

  return res.status(501).json({
    error: 'Provider adapter not configured'
  });
});

// Telegram bot commands
bot.start(async (ctx) => {
  try {
    const payload = ctx.startPayload || '';
    const refMatch = payload.match(/^ref_(\d+)$/);
    const referralId = refMatch
      ? Number(refMatch[1])
      : null;

    await saveUser(ctx.from, referralId);

    const keyboard = Markup.inlineKeyboard([
      [
        Markup.button.webApp(
          '🚀 Open Reward App',
          cfg.appUrl
        )
      ]
    ]);

    await ctx.reply(
      `Welcome ${ctx.from.first_name || 'friend'}!\n\nOpen the Reward App to view your balance, tasks and withdrawals.`,
      keyboard
    );

  } catch (error) {
    console.error('Start error:', error);
    ctx.reply(
      'Sorry, setup failed. Please try again later.'
    );
  }
});

bot.command('id', (ctx) => {
  ctx.reply(`Your Telegram ID: ${ctx.from.id}`);
});

bot.command('menu', (ctx) => {
  ctx.reply(
    'Open your Reward App:',
    Markup.inlineKeyboard([
      [
        Markup.button.webApp(
          '🚀 Open Reward App',
          cfg.appUrl
        )
      ]
    ])
  );
});

bot.command('withdrawals', async (ctx) => {
  if (ctx.from.id !== cfg.adminId) {
    return ctx.reply('Not authorized.');
  }

  const { data, error } = await supabase
    .from('withdrawals')
    .select(
      'id, telegram_id, amount, payment_method, status'
    )
    .eq('status', 'pending')
    .order('created_at', { ascending: true })
    .limit(10);

  if (error) {
    console.error(error);
    return ctx.reply('Could not load withdrawals.');
  }

  if (!data.length) {
    return ctx.reply('No pending withdrawals.');
  }

  for (const item of data) {
    await ctx.reply(
      `Withdrawal: ${item.id}\nUser: ${item.telegram_id}\nAmount: $${(Number(item.amount) / 1000000).toFixed(6)} USDT\nMethod: ${item.payment_method}\nWallet: ${item.payment_details}`,
      Markup.inlineKeyboard([
        [
          Markup.button.callback(
            'Approve',
            `wd_approve_${item.id}`
          ),
          Markup.button.callback(
            'Reject + Refund',
            `wd_reject_${item.id}`
          )
        ]
      ])
    );
  }
});

bot.action(
  /^wd_(approve|reject)_([0-9a-f-]+)$/i,
  async (ctx) => {
    if (ctx.from.id !== cfg.adminId) {
      return ctx.answerCbQuery(
        'Not authorized',
        { show_alert: true }
      );
    }

    try {
      const approve = ctx.match[1] === 'approve';
      const id = ctx.match[2];

      const { data, error } = await supabase.rpc(
        'process_withdrawal',
        {
          p_id: id,
          p_admin: cfg.adminId,
          p_approve: approve,
          p_authorized_admin: cfg.adminId
        }
      );

      if (error) throw error;

      if (!data.ok) {
        return ctx.answerCbQuery(
          data.reason || 'Could not process'
        );
      }

      await ctx.editMessageText(
        `Withdrawal ${approve ? 'approved' : 'rejected and refunded'}.\nID: ${id}`
      );

      await ctx.answerCbQuery('Done');

    } catch (error) {
      console.error('Admin action error:', error);
      await ctx.answerCbQuery(
        'Action failed',
        { show_alert: true }
      );
    }
  }
);

bot.catch((error) => {
  console.error('Telegram bot error:', error);
});

const server = app.listen(cfg.port, () => {
  console.log(`Server listening on port ${cfg.port}`);
});

(async () => {
  try {
    const me = await bot.telegram.getMe();
    botUsername = me.username || '';

    await bot.launch();

    console.log(
      `Telegram bot started${botUsername ? ` as @${botUsername}` : ''}`
    );

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
