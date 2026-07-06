// ============================================================
// Cloudflare Worker 后端 - 最终生产版 v9.1
// 修复：CORS_ORIGIN 环境变量正确读取
// 状态：✅ 可直接部署上线
// ============================================================

import { jwtVerify } from 'https://deno.land/x/jose@v4.14.4/index.js';

// ===================== 配置 =====================
const AI_API_URL = 'https://api.deepseek.com/v1/chat/completions';
const RATE_LIMIT_WINDOW = 3600;
const RATE_LIMIT_MAX = 50;
const IP_RATE_LIMIT_MAX = 200;
const MAX_EXPORT_MESSAGES = 500;
const MAX_EXPORT_TOTAL_MESSAGES = 5000;
const MAX_IMAGE_SIZE = 1 * 1024 * 1024;
const MAX_MESSAGES_PER_REQUEST = 200;
const MAX_IMPORT_TOTAL_MESSAGES = 5000;
const BATCH_CHUNK_SIZE = 50;
const IMPORT_BATCH_SIZE = 100;
const SHARE_EXPIRY_DAYS = 7;
const MAX_SINGLE_MESSAGE_LENGTH = 50000;
const MAX_TOTAL_CHARS_PER_REQUEST = 200000;
const RECOVERY_CODE_EXPIRY_DAYS = 7;
const MAX_RECOVERY_CODES = 8;

// ===================== 启动校验 =====================
function validateEnv(env) {
    const required = ['SUPABASE_JWT_SECRET', 'AI_API_KEY'];
    const missing = required.filter(key => !env[key]);
    if (missing.length > 0) {
        throw new Error(`缺少必需的环境变量: ${missing.join(', ')}`);
    }
    if (!env.CORS_ORIGIN) {
        console.warn('⚠️ CORS_ORIGIN 未设置，默认允许所有来源');
    }
    console.log('✅ 环境变量校验通过');
    return true;
}

// ===================== 辅助函数 =====================
function jsonResponse(data, status = 200, env, extraHeaders = {}) {
    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': getCorsOrigin(env),
        ...extraHeaders,
    };
    return new Response(JSON.stringify(data), { status, headers });
}

function errorResponse(message, status = 400, env, extraHeaders = {}) {
    return jsonResponse({ error: message }, status, env, extraHeaders);
}

function generateId() {
    return Math.random().toString(36).substring(2, 8) + Date.now().toString(36);
}

function generateRecoveryCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
        code += chars[Math.floor(Math.random() * chars.length)];
    }
    return code.slice(0, 4) + '-' + code.slice(4);
}

function getCorsOrigin(env) {
    return env?.CORS_ORIGIN || '*';
}

function generateCacheHeaders(data, timestamp) {
    const headers = {};
    if (timestamp) {
        headers['Last-Modified'] = new Date(timestamp * 1000).toUTCString();
    }
    return headers;
}

// ===================== 身份识别 =====================
async function identifyUser(request, env) {
    const auth = request.headers.get('Authorization');
    const deviceId = request.headers.get('X-Device-Id');

    if (!deviceId) {
        throw new Error('Missing X-Device-Id header');
    }

    if (auth && auth.startsWith('Bearer ')) {
        try {
            const { payload } = await jwtVerify(
                auth.slice(7),
                new TextEncoder().encode(env.SUPABASE_JWT_SECRET)
            );
            return {
                userId: payload.sub,
                isAuthenticated: true,
                isAnonymous: false,
                deviceId: deviceId
            };
        } catch (e) {
            // JWT无效，继续尝试设备ID
        }
    }

    return {
        userId: 'anon_' + deviceId,
        isAuthenticated: false,
        isAnonymous: true,
        deviceId: deviceId
    };
}

// ===================== 用户保障 =====================
async function ensureUser(userId, env) {
    await env.DB.prepare(
        'INSERT OR IGNORE INTO users (id, settings, is_anonymous) VALUES (?, ?, ?)'
    ).bind(userId, '{}', userId.startsWith('anon_') ? 1 : 0).run();
}

// ===================== 限流 =====================
async function checkAndRecordRateLimit(userId, env, ip) {
    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - RATE_LIMIT_WINDOW;

    const { results: userResults } = await env.DB.prepare(
        `SELECT COUNT(*) as cnt FROM request_logs 
         WHERE user_id = ? AND timestamp > ?`
    ).bind(userId, windowStart).all();

    const userCount = userResults[0]?.cnt || 0;

    let ipCount = 0;
    if (ip) {
        const { results: ipResults } = await env.DB.prepare(
            `SELECT COUNT(*) as cnt FROM request_logs 
             WHERE ip = ? AND timestamp > ?`
        ).bind(ip, windowStart).all();
        ipCount = ipResults[0]?.cnt || 0;
    }

    const allowed = userCount < RATE_LIMIT_MAX && ipCount < IP_RATE_LIMIT_MAX;

    await env.DB.prepare(
        `INSERT INTO request_logs (user_id, timestamp, ip) VALUES (?, ?, ?)`
    ).bind(userId, now, ip || null).run();

    env.DB.prepare(
        `DELETE FROM request_logs WHERE timestamp < ?`
    ).bind(now - 7 * 24 * 3600).run().catch(() => {});

    return allowed;
}

// ===================== 输入校验 =====================
function validateChatRequest(body) {
    if (body.temperature !== undefined) {
        body.temperature = Math.min(Math.max(body.temperature, 0), 2);
    }
    if (body.max_tokens !== undefined) {
        body.max_tokens = Math.min(Math.max(body.max_tokens, 1024), 32768);
    }

    if (body.messages && Array.isArray(body.messages)) {
        if (body.messages.length > MAX_MESSAGES_PER_REQUEST) {
            throw new Error(`消息数量不能超过 ${MAX_MESSAGES_PER_REQUEST} 条`);
        }

        let totalChars = 0;
        for (const msg of body.messages) {
            if (Array.isArray(msg.content)) {
                for (const part of msg.content) {
                    if (part.type === 'image_url' && part.image_url?.url) {
                        const url = part.image_url.url;
                        if (url.startsWith('http://') || url.startsWith('https://')) {
                            throw new Error('不支持外部图片链接，请上传图片文件');
                        }
                        if (url.startsWith('data:image/')) {
                            const base64Data = url.split(',')[1] || '';
                            const size = Math.ceil(base64Data.length * 0.75);
                            if (size > MAX_IMAGE_SIZE) {
                                throw new Error('图片大小超过 1MB 限制');
                            }
                        }
                    }
                }
            }
            if (typeof msg.content === 'string') {
                if (msg.content.length > MAX_SINGLE_MESSAGE_LENGTH) {
                    throw new Error(`单条消息内容过长（最多 ${MAX_SINGLE_MESSAGE_LENGTH} 字符）`);
                }
                totalChars += msg.content.length;
            }
        }

        if (totalChars > MAX_TOTAL_CHARS_PER_REQUEST) {
            throw new Error(`消息总字符数超过 ${MAX_TOTAL_CHARS_PER_REQUEST}，请精简后重试`);
        }
    }

    if (body.limitless) {
        body.max_tokens = Math.min(body.max_tokens || 8192, 32768);
        if (body.temperature > 0.5) body.temperature = 0.5;
    }

    return body;
}

// ===================== 分块批量执行 =====================
async function batchExecute(db, queries, chunkSize = BATCH_CHUNK_SIZE) {
    for (let i = 0; i < queries.length; i += chunkSize) {
        const chunk = queries.slice(i, i + chunkSize);
        await db.batch(chunk);
    }
}

// ===================== 获取会话最新更新时间 =====================
async function getSessionsLastUpdated(db, userId) {
    const result = await db.prepare(
        'SELECT MAX(updated_at) as max_updated FROM sessions WHERE user_id = ?'
    ).bind(userId).first();
    return result?.max_updated || null;
}

// ===================== 删除用户所有数据 =====================
async function deleteUserData(db, userId) {
    await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM request_logs WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM device_bindings WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();
}

// ===================== 合并匿名数据到登录用户 =====================
async function mergeAnonymousData(db, anonymousUserId, targetUserId) {
    const anonUser = await db.prepare(
        'SELECT id FROM users WHERE id = ?'
    ).bind(anonymousUserId).first();

    if (!anonUser) {
        return { mergedSessions: 0, cleanedLogs: 0, message: '无匿名数据需要合并' };
    }

    const { results: sessions } = await db.prepare(
        'SELECT id FROM sessions WHERE user_id = ?'
    ).bind(anonymousUserId).all();

    const { results: allRecoveryCodes } = await db.prepare(
        'SELECT id, used_at FROM device_bindings WHERE user_id = ?'
    ).bind(anonymousUserId).all();

    if (sessions.length === 0 && allRecoveryCodes.length === 0) {
        await db.prepare('DELETE FROM users WHERE id = ?').bind(anonymousUserId).run();
        return { mergedSessions: 0, cleanedLogs: 0, message: '无有效数据需要合并' };
    }

    let mergedSessions = 0;
    let deletedUnusedCodes = 0;
    let deletedUsedCodes = 0;

    await db.exec('BEGIN TRANSACTION');

    try {
        // 1. 迁移会话
        for (const s of sessions) {
            const existing = await db.prepare(
                'SELECT id FROM sessions WHERE id = ? AND user_id = ?'
            ).bind(s.id, targetUserId).first();

            if (!existing) {
                await db.prepare(
                    `UPDATE sessions SET user_id = ? WHERE id = ? AND user_id = ?`
                ).bind(targetUserId, s.id, anonymousUserId).run();
                mergedSessions++;
            }
        }

        // 2. 删除所有恢复码（登录用户不需要恢复码）
        for (const rc of allRecoveryCodes) {
            if (rc.used_at === null) {
                deletedUnusedCodes++;
            } else {
                deletedUsedCodes++;
            }
            await db.prepare('DELETE FROM device_bindings WHERE id = ?').bind(rc.id).run();
        }

        // 3. 删除匿名用户的请求日志
        const logResult = await db.prepare(
            'DELETE FROM request_logs WHERE user_id = ?'
        ).bind(anonymousUserId).run();
        const cleanedLogs = logResult.meta.changes || 0;

        // 4. 删除匿名用户
        await db.prepare('DELETE FROM users WHERE id = ?').bind(anonymousUserId).run();

        await db.exec('COMMIT');

        return {
            mergedSessions: mergedSessions,
            cleanedLogs: cleanedLogs,
            message: `成功合并 ${mergedSessions} 个会话，清理 ${deletedUsedCodes} 个已使用恢复码和 ${deletedUnusedCodes} 个未使用恢复码`
        };

    } catch (err) {
        await db.exec('ROLLBACK');
        throw err;
    }
}

// ===================== gzip压缩辅助函数 =====================
async function compressData(data) {
    try {
        const stream = new Blob([data]).stream();
        const compressedStream = stream.pipeThrough(new CompressionStream('gzip'));
        const compressedBlob = await new Response(compressedStream).blob();
        return await compressedBlob.arrayBuffer();
    } catch (e) {
        return null;
    }
}

// ============================================================
// 主处理器
// ============================================================
export default {
    async fetch(request, env) {
        // ---------- 启动校验 ----------
        try {
            validateEnv(env);
        } catch (err) {
            return new Response(JSON.stringify({ error: err.message }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        // ---------- CORS ----------
        if (method === 'OPTIONS') {
            return new Response(null, {
                headers: {
                    'Access-Control-Allow-Origin': getCorsOrigin(env),
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Device-Id',
                }
            });
        }

        // ---------- 健康检查 ----------
        if (path === '/health' && method === 'GET') {
            try {
                await env.DB.prepare('SELECT 1').all();
                return jsonResponse({
                    status: 'ok',
                    db: 'connected',
                    timestamp: new Date().toISOString(),
                    version: '9.1'
                }, 200, env);
            } catch (e) {
                return jsonResponse({ status: 'degraded', db: 'disconnected', error: e.message }, 503, env);
            }
        }

        // ---------- 身份识别 ----------
        let identity;
        try {
            identity = await identifyUser(request, env);
        } catch (err) {
            return errorResponse(err.message || 'Missing X-Device-Id header', 400, env);
        }

        const { userId, isAuthenticated, isAnonymous, deviceId } = identity;
        const isPublicShare = path.startsWith('/share/') && method === 'GET';
        const isRecoveryPublic = path === '/device/restore' && method === 'POST';

        // ---------- 登录用户自动合并匿名数据 ----------
        let mergeResult = null;
        if (isAuthenticated && deviceId && !isPublicShare && !isRecoveryPublic) {
            const anonymousUserId = 'anon_' + deviceId;
            const anonUser = await env.DB.prepare(
                'SELECT id FROM users WHERE id = ?'
            ).bind(anonymousUserId).first();

            if (anonUser) {
                try {
                    mergeResult = await mergeAnonymousData(env.DB, anonymousUserId, userId);
                    if (mergeResult.mergedSessions > 0) {
                        console.log(`合并完成: ${mergeResult.mergedSessions} 会话`);
                    }
                } catch (err) {
                    console.error('合并匿名数据失败:', err);
                }
            }
        }

        // 确保用户存在
        if (!isPublicShare && !isRecoveryPublic) {
            await ensureUser(userId, env);
        }

        const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || null;

        try {
            // ============================================================
            // 恢复码验证（公开接口）
            // ============================================================
            if (path === '/device/restore' && method === 'POST') {
                const body = await request.json();
                const rawCode = body.code?.trim().toUpperCase() || '';
                const code = rawCode.replace(/-/g, '');

                if (!code || code.length !== 8) {
                    return errorResponse('无效的恢复码格式', 400, env);
                }

                const targetDeviceId = request.headers.get('X-Device-Id');
                if (!targetDeviceId) {
                    return errorResponse('缺少设备标识', 400, env);
                }
                const targetUserId = 'anon_' + targetDeviceId;
                const now = Math.floor(Date.now() / 1000);

                await env.DB.exec('BEGIN TRANSACTION');

                try {
                    const updateResult = await env.DB.prepare(
                        `UPDATE device_bindings SET used_at = ?, used_by = ?
                         WHERE code = ? AND used_at IS NULL AND expires_at > ?`
                    ).bind(now, targetUserId, code, now).run();

                    if (updateResult.meta.changes === 0) {
                        await env.DB.exec('ROLLBACK');
                        return errorResponse('恢复码无效、已使用或已过期', 404, env);
                    }

                    const binding = await env.DB.prepare(
                        'SELECT user_id FROM device_bindings WHERE code = ?'
                    ).bind(code).first();

                    if (!binding) {
                        await env.DB.exec('ROLLBACK');
                        return errorResponse('恢复码关联的用户不存在', 404, env);
                    }

                    const sourceUserId = binding.user_id;
                    const { results: sourceSessions } = await env.DB.prepare(
                        'SELECT * FROM sessions WHERE user_id = ?'
                    ).bind(sourceUserId).all();

                    let mergedCount = 0;

                    for (const s of sourceSessions) {
                        const existing = await env.DB.prepare(
                            'SELECT id FROM sessions WHERE id = ? AND user_id = ?'
                        ).bind(s.id, targetUserId).first();

                        if (!existing) {
                            await env.DB.prepare(
                                `UPDATE sessions SET user_id = ? WHERE id = ? AND user_id = ?`
                            ).bind(targetUserId, s.id, sourceUserId).run();
                            mergedCount++;
                        }
                    }

                    await env.DB.exec('COMMIT');

                    return jsonResponse({
                        success: true,
                        merged: mergedCount,
                        message: mergedCount > 0
                            ? `成功恢复 ${mergedCount} 个会话`
                            : '恢复成功，当前设备没有检测到新数据',
                        is_anonymous: true,
                    }, 200, env);

                } catch (err) {
                    await env.DB.exec('ROLLBACK');
                    throw err;
                }
            }

            // ============================================================
            // 1. AI 代理
            // ============================================================
            if (path === '/api/chat' && method === 'POST') {
                const allowed = await checkAndRecordRateLimit(userId, env, clientIP);
                if (!allowed) {
                    return errorResponse('请求过于频繁（用户每小时限制 ' + RATE_LIMIT_MAX + ' 次，IP每小时限制200次）', 429, env);
                }

                let body;
                try { body = await request.json(); } catch {
                    return errorResponse('无效的 JSON 请求体', 400, env);
                }

                try { body = validateChatRequest(body); } catch (err) {
                    return errorResponse(err.message, 400, env);
                }

                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 60000);

                try {
                    const aiRes = await fetch(env.AI_API_URL || AI_API_URL, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + env.AI_API_KEY,
                        },
                        body: JSON.stringify(body),
                        signal: controller.signal,
                    });

                    clearTimeout(timeout);

                    if (!aiRes.ok) {
                        let errorMsg = 'AI 服务错误: ' + aiRes.status;
                        try {
                            const errData = await aiRes.json();
                            if (errData.error?.message) errorMsg = errData.error.message;
                        } catch (e) {}
                        return errorResponse(errorMsg, aiRes.status, env);
                    }

                    const newHeaders = new Headers(aiRes.headers);
                    newHeaders.set('Access-Control-Allow-Origin', getCorsOrigin(env));
                    return new Response(aiRes.body, {
                        status: aiRes.status,
                        headers: newHeaders,
                    });

                } catch (err) {
                    clearTimeout(timeout);
                    if (err.name === 'AbortError') {
                        return errorResponse('AI 服务响应超时，请稍后再试', 504, env);
                    }
                    console.error('AI API 失败:', err);
                    return errorResponse('AI 服务暂时不可用', 503, env);
                }
            }

            // ============================================================
            // 2. 获取会话列表
            // ============================================================
            if (path === '/sessions' && method === 'GET') {
                const page = parseInt(url.searchParams.get('page') || '1');
                const size = parseInt(url.searchParams.get('size') || '20');
                const offset = (page - 1) * size;

                const lastUpdated = await getSessionsLastUpdated(env.DB, userId);

                const { results: totalResult } = await env.DB.prepare(
                    'SELECT COUNT(*) as total FROM sessions WHERE user_id = ?'
                ).bind(userId).all();

                const total = totalResult[0]?.total || 0;

                const { results } = await env.DB.prepare(
                    `SELECT id, name, model, created_at, updated_at, pinned, share_id, share_expires_at,
                            (SELECT COUNT(*) FROM messages WHERE session_id = sessions.id) as msg_count
                     FROM sessions WHERE user_id = ? ORDER BY updated_at DESC LIMIT ? OFFSET ?`
                ).bind(userId, size, offset).all();

                const responseData = {
                    data: results,
                    pagination: { page, size, total, total_pages: Math.ceil(total / size) }
                };

                const cacheHeaders = generateCacheHeaders(responseData, lastUpdated || Math.floor(Date.now() / 1000));
                return jsonResponse(responseData, 200, env, cacheHeaders);
            }

            // ============================================================
            // 3. 获取单个会话详情
            // ============================================================
            if (path.startsWith('/sessions/') && method === 'GET' && !path.endsWith('/share') && !path.includes('/messages')) {
                const sessionId = path.split('/')[2];
                if (!sessionId) return errorResponse('缺少会话 ID', 400, env);

                const session = await env.DB.prepare(
                    'SELECT * FROM sessions WHERE id = ? AND user_id = ?'
                ).bind(sessionId, userId).first();

                if (!session) return errorResponse('会话不存在', 404, env);

                const { results: messages } = await env.DB.prepare(
                    'SELECT * FROM messages WHERE session_id = ? ORDER BY timestamp ASC'
                ).bind(sessionId).all();

                session.messages = messages;

                const cacheHeaders = generateCacheHeaders(session, session.updated_at);
                return jsonResponse(session, 200, env, cacheHeaders);
            }

            // ============================================================
            // 4. 创建/更新会话
            // ============================================================
            if (path.startsWith('/sessions/') && method === 'PUT') {
                const sessionId = path.split('/')[2];
                if (!sessionId) return errorResponse('缺少会话 ID', 400, env);

                const body = await request.json();
                const { name, messages, token_count, model, pinned, _updated_at } = body;

                if (_updated_at === undefined || _updated_at === null) {
                    return errorResponse('请先拉取最新会话数据再保存（缺少 _updated_at）', 400, env);
                }

                const now = Math.floor(Date.now() / 1000);

                const existing = await env.DB.prepare(
                    'SELECT id, updated_at FROM sessions WHERE id = ? AND user_id = ?'
                ).bind(sessionId, userId).first();

                if (existing) {
                    const clientTime = parseInt(_updated_at);
                    const serverTime = existing.updated_at || 0;
                    if (clientTime !== serverTime) {
                        return errorResponse('会话数据已被其他设备修改，请刷新后重试', 409, env);
                    }
                }

                await env.DB.exec('BEGIN TRANSACTION');

                try {
                    const queries = [];

                    if (existing) {
                        queries.push({
                            sql: `UPDATE sessions SET name = ?, model = ?, updated_at = ?, token_count = ?, pinned = ?
                                  WHERE id = ? AND user_id = ?`,
                            args: [
                                name || '未命名',
                                model || '',
                                now,
                                token_count || 0,
                                pinned !== undefined ? (pinned ? 1 : 0) : 0,
                                sessionId,
                                userId
                            ]
                        });
                        queries.push({
                            sql: 'DELETE FROM messages WHERE session_id = ?',
                            args: [sessionId]
                        });
                    } else {
                        queries.push({
                            sql: `INSERT INTO sessions (id, user_id, name, model, created_at, updated_at, pinned, token_count)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                            args: [
                                sessionId,
                                userId,
                                name || '未命名',
                                model || '',
                                now,
                                now,
                                pinned !== undefined ? (pinned ? 1 : 0) : 0,
                                token_count || 0
                            ]
                        });
                    }

                    if (messages && Array.isArray(messages)) {
                        if (messages.length > MAX_MESSAGES_PER_REQUEST) {
                            throw new Error(`消息数量不能超过 ${MAX_MESSAGES_PER_REQUEST} 条`);
                        }
                        for (const msg of messages) {
                            queries.push({
                                sql: `INSERT INTO messages (id, session_id, role, content, timestamp, edited)
                                      VALUES (?, ?, ?, ?, ?, ?)`,
                                args: [
                                    msg.id || generateId(),
                                    sessionId,
                                    msg.role,
                                    msg.content || '',
                                    msg.timestamp || now,
                                    msg.edited ? 1 : 0
                                ]
                            });
                        }
                    }

                    await batchExecute(env.DB, queries);
                    await env.DB.exec('COMMIT');

                    return jsonResponse({ success: true, updated_at: now }, 200, env);

                } catch (err) {
                    await env.DB.exec('ROLLBACK');
                    throw err;
                }
            }

            // ============================================================
            // 5. 删除会话
            // ============================================================
            if (path.startsWith('/sessions/') && method === 'DELETE' && !path.endsWith('/share') && !path.endsWith('/messages')) {
                const sessionId = path.split('/')[2];
                if (!sessionId) return errorResponse('缺少会话 ID', 400, env);

                const existing = await env.DB.prepare(
                    'SELECT id FROM sessions WHERE id = ? AND user_id = ?'
                ).bind(sessionId, userId).first();

                if (!existing) return errorResponse('会话不存在或无权限', 404, env);

                await env.DB.prepare('DELETE FROM sessions WHERE id = ? AND user_id = ?')
                    .bind(sessionId, userId).run();

                return jsonResponse({ success: true }, 200, env);
            }

            // ============================================================
            // 6. 清空会话消息
            // ============================================================
            if (path.startsWith('/sessions/') && path.endsWith('/messages') && method === 'DELETE') {
                const sessionId = path.split('/')[2];
                if (!sessionId) return errorResponse('缺少会话 ID', 400, env);

                const existing = await env.DB.prepare(
                    'SELECT id FROM sessions WHERE id = ? AND user_id = ?'
                ).bind(sessionId, userId).first();

                if (!existing) return errorResponse('会话不存在或无权限', 404, env);

                await env.DB.prepare('DELETE FROM messages WHERE session_id = ?')
                    .bind(sessionId).run();

                const now = Math.floor(Date.now() / 1000);
                await env.DB.prepare(
                    'UPDATE sessions SET updated_at = ? WHERE id = ? AND user_id = ?'
                ).bind(now, sessionId, userId).run();

                return jsonResponse({ success: true, message: '会话消息已清空' }, 200, env);
            }

            // ============================================================
            // 7. 分享会话
            // ============================================================
            if (path.startsWith('/sessions/') && path.endsWith('/share') && method === 'POST') {
                const sessionId = path.split('/')[2];
                if (!sessionId) return errorResponse('缺少会话 ID', 400, env);

                const session = await env.DB.prepare(
                    'SELECT * FROM sessions WHERE id = ? AND user_id = ?'
                ).bind(sessionId, userId).first();

                if (!session) return errorResponse('会话不存在或无权限', 404, env);

                const shareId = generateId();
                const expiresAt = Math.floor(Date.now() / 1000) + SHARE_EXPIRY_DAYS * 24 * 3600;

                await env.DB.prepare(
                    'UPDATE sessions SET share_id = ?, share_expires_at = ? WHERE id = ? AND user_id = ?'
                ).bind(shareId, expiresAt, sessionId, userId).run();

                return jsonResponse({
                    share_id: shareId,
                    expires_at: new Date(expiresAt * 1000).toISOString(),
                }, 200, env);
            }

            // ============================================================
            // 8. 取消分享
            // ============================================================
            if (path.startsWith('/sessions/') && path.endsWith('/share') && method === 'DELETE') {
                const sessionId = path.split('/')[2];
                if (!sessionId) return errorResponse('缺少会话 ID', 400, env);

                const session = await env.DB.prepare(
                    'SELECT share_id FROM sessions WHERE id = ? AND user_id = ?'
                ).bind(sessionId, userId).first();

                if (!session) return errorResponse('会话不存在或无权限', 404, env);
                if (!session.share_id) return errorResponse('该会话未分享', 404, env);

                await env.DB.prepare(
                    'UPDATE sessions SET share_id = NULL, share_expires_at = NULL WHERE id = ? AND user_id = ?'
                ).bind(sessionId, userId).run();

                return jsonResponse({ success: true }, 200, env);
            }

            // ============================================================
            // 9. 获取分享内容（公开）
            // ============================================================
            if (path.startsWith('/share/') && method === 'GET') {
                const shareId = path.split('/')[2];
                if (!shareId) return errorResponse('缺少分享 ID', 400, env);

                const session = await env.DB.prepare(
                    'SELECT id, name, model, created_at, updated_at, share_expires_at FROM sessions WHERE share_id = ?'
                ).bind(shareId).first();

                if (!session) return errorResponse('分享不存在或已过期', 404, env);

                const now = Math.floor(Date.now() / 1000);
                if (session.share_expires_at && session.share_expires_at < now) {
                    return errorResponse('分享链接已过期', 410, env);
                }

                const { results: messages } = await env.DB.prepare(
                    'SELECT id, role, content, timestamp, edited FROM messages WHERE session_id = ? ORDER BY timestamp ASC'
                ).bind(session.id).all();

                return jsonResponse({
                    session: {
                        id: session.id,
                        name: session.name,
                        model: session.model,
                        created_at: session.created_at,
                        updated_at: session.updated_at,
                        messages: messages,
                    },
                    shared_at: new Date().toISOString(),
                    expires_at: session.share_expires_at ? new Date(session.share_expires_at * 1000).toISOString() : null,
                }, 200, env);
            }

            // ============================================================
            // 10. 获取用户设置
            // ============================================================
            if (path === '/profile' && method === 'GET') {
                const user = await env.DB.prepare(
                    'SELECT settings FROM users WHERE id = ?'
                ).bind(userId).first();

                try {
                    const settings = JSON.parse(user?.settings || '{}');
                    return jsonResponse({ settings }, 200, env);
                } catch {
                    return jsonResponse({ settings: {} }, 200, env);
                }
            }

            // ============================================================
            // 11. 更新用户设置
            // ============================================================
            if (path === '/profile' && method === 'PUT') {
                const body = await request.json();
                const settings = body.settings || {};

                await env.DB.prepare(
                    'UPDATE users SET settings = ? WHERE id = ?'
                ).bind(JSON.stringify(settings), userId).run();

                return jsonResponse({ success: true }, 200, env);
            }

            // ============================================================
            // 12. 恢复码生成（仅匿名，最多8个）
            // ============================================================
            if (path === '/device/recovery' && method === 'POST') {
                if (isAuthenticated) {
                    return errorResponse('已登录用户无需恢复码，请使用账号登录', 400, env);
                }

                const now = Math.floor(Date.now() / 1000);

                const { results: countResult } = await env.DB.prepare(
                    'SELECT COUNT(*) as cnt FROM device_bindings WHERE user_id = ? AND used_at IS NULL AND expires_at > ?'
                ).bind(userId, now).all();

                const currentCount = countResult[0]?.cnt || 0;
                if (currentCount >= MAX_RECOVERY_CODES) {
                    return errorResponse(`恢复码数量已达上限（${MAX_RECOVERY_CODES}个），请先撤销旧码再生成新码`, 400, env);
                }

                const existing = await env.DB.prepare(
                    'SELECT code, expires_at FROM device_bindings WHERE user_id = ? AND used_at IS NULL AND expires_at > ? LIMIT 1'
                ).bind(userId, now).first();

                if (existing) {
                    const formatted = existing.code.slice(0, 4) + '-' + existing.code.slice(4);
                    return jsonResponse({
                        code: formatted,
                        expires_at: new Date(existing.expires_at * 1000).toISOString(),
                        is_new: false,
                        total_active: currentCount,
                        max_allowed: MAX_RECOVERY_CODES,
                    }, 200, env);
                }

                const rawCode = generateRecoveryCode().replace(/-/g, '');
                const expiresAt = now + RECOVERY_CODE_EXPIRY_DAYS * 24 * 3600;

                await env.DB.prepare(
                    'INSERT INTO device_bindings (code, user_id, expires_at) VALUES (?, ?, ?)'
                ).bind(rawCode, userId, expiresAt).run();

                const formatted = rawCode.slice(0, 4) + '-' + rawCode.slice(4);

                return jsonResponse({
                    code: formatted,
                    expires_at: new Date(expiresAt * 1000).toISOString(),
                    is_new: true,
                    total_active: currentCount + 1,
                    max_allowed: MAX_RECOVERY_CODES,
                    message: `恢复码已生成（${currentCount + 1}/${MAX_RECOVERY_CODES}），请在另一台设备上输入此码即可同步数据`,
                }, 200, env);
            }

            // ============================================================
            // 13. 恢复码列表
            // ============================================================
            if (path === '/device/recovery-codes' && method === 'GET') {
                const now = Math.floor(Date.now() / 1000);
                const { results } = await env.DB.prepare(
                    `SELECT code, expires_at, used_at, used_by, created_at
                     FROM device_bindings
                     WHERE user_id = ?
                     ORDER BY created_at DESC`
                ).bind(userId).all();

                const codes = results.map(r => ({
                    code: r.code.slice(0, 4) + '-' + r.code.slice(4),
                    expires_at: new Date(r.expires_at * 1000).toISOString(),
                    is_used: r.used_at !== null,
                    used_by: r.used_by || null,
                    used_at: r.used_at ? new Date(r.used_at * 1000).toISOString() : null,
                    created_at: new Date(r.created_at * 1000).toISOString(),
                    is_expired: r.expires_at < now,
                }));

                const activeCount = codes.filter(c => !c.is_used && !c.is_expired).length;

                return jsonResponse({
                    codes: codes,
                    active_count: activeCount,
                    max_allowed: MAX_RECOVERY_CODES,
                }, 200, env);
            }

            // ============================================================
            // 14. 撤销恢复码
            // ============================================================
            if (path.startsWith('/device/recovery-codes/') && method === 'DELETE') {
                const codeParam = path.split('/')[3];
                if (!codeParam) return errorResponse('缺少恢复码', 400, env);

                const code = codeParam.replace(/-/g, '');
                if (code.length !== 8) return errorResponse('无效的恢复码格式', 400, env);

                const existing = await env.DB.prepare(
                    'SELECT id FROM device_bindings WHERE code = ? AND user_id = ? AND used_at IS NULL'
                ).bind(code, userId).first();

                if (!existing) {
                    return errorResponse('恢复码不存在或已被使用', 404, env);
                }

                await env.DB.prepare(
                    'DELETE FROM device_bindings WHERE code = ? AND user_id = ?'
                ).bind(code, userId).run();

                return jsonResponse({ success: true, message: '恢复码已撤销' }, 200, env);
            }

            // ============================================================
            // 15. 查询当前用户身份
            // ============================================================
            if (path === '/whoami' && method === 'GET') {
                let hasRecovery = false;
                let recoveryInfo = null;

                const now = Math.floor(Date.now() / 1000);
                const recovery = await env.DB.prepare(
                    'SELECT code, expires_at FROM device_bindings WHERE user_id = ? AND used_at IS NULL AND expires_at > ? LIMIT 1'
                ).bind(userId, now).first();

                if (recovery) {
                    hasRecovery = true;
                    recoveryInfo = {
                        code: recovery.code.slice(0, 4) + '-' + recovery.code.slice(4),
                        expires_at: new Date(recovery.expires_at * 1000).toISOString(),
                    };
                }

                const { results: countResult } = await env.DB.prepare(
                    'SELECT COUNT(*) as cnt FROM device_bindings WHERE user_id = ? AND used_at IS NULL AND expires_at > ?'
                ).bind(userId, now).all();
                const activeRecoveryCount = countResult[0]?.cnt || 0;

                return jsonResponse({
                    userId: userId,
                    isAuthenticated: isAuthenticated,
                    isAnonymous: isAnonymous,
                    deviceId: deviceId,
                    hasRecoveryCode: hasRecovery,
                    recoveryInfo: recoveryInfo,
                    activeRecoveryCount: activeRecoveryCount,
                    maxRecoveryCodes: MAX_RECOVERY_CODES,
                    mergeResult: mergeResult ? {
                        mergedSessions: mergeResult.mergedSessions,
                        message: mergeResult.message,
                    } : null,
                }, 200, env);
            }

            // ============================================================
            // 16. 导出数据
            // ============================================================
            if (path === '/export' && method === 'GET') {
                const { results: sessions } = await env.DB.prepare(
                    'SELECT * FROM sessions WHERE user_id = ? ORDER BY updated_at DESC'
                ).bind(userId).all();

                const user = await env.DB.prepare(
                    'SELECT settings FROM users WHERE id = ?'
                ).bind(userId).first();
                const settings = user ? JSON.parse(user.settings || '{}') : {};

                const sessionsObj = {};
                let totalMessages = 0;

                for (const s of sessions) {
                    const { results: msgs } = await env.DB.prepare(
                        'SELECT * FROM messages WHERE session_id = ? ORDER BY timestamp ASC LIMIT ?'
                    ).bind(s.id, MAX_EXPORT_MESSAGES).all();

                    totalMessages += msgs.length;
                    if (totalMessages > MAX_EXPORT_TOTAL_MESSAGES) {
                        const remaining = MAX_EXPORT_TOTAL_MESSAGES - (totalMessages - msgs.length);
                        if (remaining <= 0) break;
                        s.messages = msgs.slice(0, remaining);
                        s._truncated = true;
                    } else {
                        s.messages = msgs;
                    }
                    sessionsObj[s.id] = s;
                }

                const responseData = {
                    version: 3,
                    export_time: new Date().toISOString(),
                    user_id: userId,
                    settings: settings,
                    sessions: sessionsObj,
                    _note: totalMessages > MAX_EXPORT_TOTAL_MESSAGES ? '部分消息已截断（导出上限 ' + MAX_EXPORT_TOTAL_MESSAGES + ' 条）' : undefined,
                };

                const jsonStr = JSON.stringify(responseData);
                const encoder = new TextEncoder();
                const data = encoder.encode(jsonStr);

                if (data.length > 1024) {
                    const compressed = await compressData(data);
                    if (compressed) {
                        return new Response(compressed, {
                            status: 200,
                            headers: {
                                'Content-Type': 'application/json',
                                'Content-Encoding': 'gzip',
                                'Access-Control-Allow-Origin': getCorsOrigin(env),
                            }
                        });
                    }
                }

                return jsonResponse(responseData, 200, env);
            }

            // ============================================================
            // 17. 导入数据
            // ============================================================
            if (path === '/import' && method === 'POST') {
                const importData = await request.json();
                if (!importData.sessions || typeof importData.sessions !== 'object') {
                    return errorResponse('无效的备份格式：sessions 必须是对象', 400, env);
                }

                if (importData.settings) {
                    await env.DB.prepare(
                        'UPDATE users SET settings = ? WHERE id = ?'
                    ).bind(JSON.stringify(importData.settings), userId).run();
                }

                let mergedCount = 0;
                let totalInserted = 0;
                const now = Math.floor(Date.now() / 1000);

                const sessionsEntries = Object.entries(importData.sessions);
                let batchQueries = [];

                const commitBatch = async () => {
                    if (batchQueries.length === 0) return;
                    await env.DB.exec('BEGIN TRANSACTION');
                    try {
                        await batchExecute(env.DB, batchQueries);
                        await env.DB.exec('COMMIT');
                    } catch (err) {
                        await env.DB.exec('ROLLBACK');
                        throw err;
                    }
                    batchQueries = [];
                };

                try {
                    for (const [id, s] of sessionsEntries) {
                        if (mergedCount >= 100) break;
                        if (totalInserted >= MAX_IMPORT_TOTAL_MESSAGES) break;

                        const existing = await env.DB.prepare(
                            'SELECT id, updated_at FROM sessions WHERE id = ? AND user_id = ?'
                        ).bind(id, userId).first();

                        if (existing && existing.updated_at >= (s.updated_at || 0)) {
                            continue;
                        }

                        const queries = [];

                        if (existing) {
                            queries.push({
                                sql: `UPDATE sessions SET name = ?, model = ?, updated_at = ?, pinned = ?
                                      WHERE id = ? AND user_id = ?`,
                                args: [s.name || '未命名', s.model || '', s.updated_at || now, s.pinned ? 1 : 0, id, userId]
                            });
                            queries.push({
                                sql: 'DELETE FROM messages WHERE session_id = ?',
                                args: [id]
                            });
                        } else {
                            queries.push({
                                sql: `INSERT INTO sessions (id, user_id, name, model, created_at, updated_at, pinned)
                                      VALUES (?, ?, ?, ?, ?, ?, ?)`,
                                args: [id, userId, s.name || '未命名', s.model || '', s.created_at || now, s.updated_at || now, s.pinned ? 1 : 0]
                            });
                        }

                        if (s.messages && Array.isArray(s.messages)) {
                            const remaining = MAX_IMPORT_TOTAL_MESSAGES - totalInserted;
                            const msgsToInsert = s.messages.slice(0, Math.min(MAX_MESSAGES_PER_REQUEST, remaining));
                            for (const msg of msgsToInsert) {
                                queries.push({
                                    sql: `INSERT INTO messages (id, session_id, role, content, timestamp, edited)
                                          VALUES (?, ?, ?, ?, ?, ?)`,
                                    args: [msg.id || generateId(), id, msg.role, msg.content || '', msg.timestamp || now, msg.edited ? 1 : 0]
                                });
                                totalInserted++;
                            }
                        }

                        batchQueries = batchQueries.concat(queries);

                        if (batchQueries.length >= IMPORT_BATCH_SIZE) {
                            await commitBatch();
                        }

                        mergedCount++;
                    }

                    await commitBatch();

                } catch (err) {
                    await env.DB.exec('ROLLBACK').catch(() => {});
                    throw err;
                }

                return jsonResponse({
                    success: true,
                    merged: mergedCount,
                    messages_inserted: totalInserted,
                }, 200, env);
            }

            // ============================================================
            // 18. 插件列表
            // ============================================================
            if (path === '/plugins' && method === 'GET') {
                const { results } = await env.DB.prepare(
                    'SELECT id, name, description, version, author, downloads FROM plugins WHERE approved = 1 ORDER BY downloads DESC'
                ).all();
                return jsonResponse(results, 200, env);
            }

            // ============================================================
            // 19. 获取单个插件
            // ============================================================
            if (path.startsWith('/plugins/') && method === 'GET') {
                const pluginId = path.split('/')[2];
                if (!pluginId) return errorResponse('缺少插件 ID', 400, env);

                const plugin = await env.DB.prepare(
                    'SELECT id, name, description, code, version, author, downloads, created_at, updated_at FROM plugins WHERE id = ? AND approved = 1'
                ).bind(pluginId).first();

                if (!plugin) return errorResponse('插件不存在或未审核', 404, env);

                env.DB.prepare('UPDATE plugins SET downloads = downloads + 1 WHERE id = ?')
                    .bind(pluginId).run().catch(() => {});

                return jsonResponse(plugin, 200, env);
            }

            // ============================================================
            // 20. 会话搜索
            // ============================================================
            if (path === '/sessions/search' && method === 'GET') {
                const query = url.searchParams.get('q');
                if (!query || query.trim().length < 1) {
                    return errorResponse('请提供搜索关键词 q', 400, env);
                }

                const searchTerm = '%' + query.trim() + '%';

                const { results } = await env.DB.prepare(
                    `SELECT DISTINCT s.id, s.name, s.model, s.created_at, s.updated_at, s.pinned,
                            (SELECT COUNT(*) FROM messages WHERE session_id = s.id) as msg_count
                     FROM sessions s
                     INNER JOIN messages m ON s.id = m.session_id
                     WHERE s.user_id = ? AND m.content LIKE ?
                     ORDER BY s.updated_at DESC
                     LIMIT 50`
                ).bind(userId, searchTerm).all();

                return jsonResponse({
                    query: query.trim(),
                    results: results,
                    count: results.length,
                }, 200, env);
            }

            // ============================================================
            // 21. 删除用户所有数据
            // ============================================================
            if (path === '/user' && method === 'DELETE') {
                await deleteUserData(env.DB, userId);
                return jsonResponse({
                    success: true,
                    message: '用户所有数据已删除',
                }, 200, env);
            }

            // ============================================================
            // 22. 批量删除会话
            // ============================================================
            if (path === '/sessions' && method === 'DELETE') {
                const idsParam = url.searchParams.get('ids');
                if (!idsParam) {
                    return errorResponse('请提供 ids 参数（逗号分隔的会话ID列表）', 400, env);
                }

                const ids = idsParam.split(',').filter(id => id.trim());
                if (ids.length === 0) {
                    return errorResponse('至少提供一个会话ID', 400, env);
                }

                let deletedCount = 0;
                for (const id of ids) {
                    const trimmedId = id.trim();
                    const existing = await env.DB.prepare(
                        'SELECT id FROM sessions WHERE id = ? AND user_id = ?'
                    ).bind(trimmedId, userId).first();

                    if (existing) {
                        await env.DB.prepare('DELETE FROM sessions WHERE id = ? AND user_id = ?')
                            .bind(trimmedId, userId).run();
                        deletedCount++;
                    }
                }

                return jsonResponse({
                    success: true,
                    deleted: deletedCount,
                    requested: ids.length,
                }, 200, env);
            }

            return errorResponse('Not Found', 404, env);

        } catch (err) {
            console.error('Unhandled error:', err);
            return errorResponse('服务器内部错误: ' + err.message, 500, env);
        }
    }
};