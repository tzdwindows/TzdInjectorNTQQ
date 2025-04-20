const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const fs = require('fs').promises;
const http = require('http');
const url = require('url');

const PRELOAD_SCRIPT_PATH = path.join(
    __dirname,
    'render.js'
)

async function checkPreloadScript() {
    try {
        await fs.access(PRELOAD_SCRIPT_PATH);
        return true;
    } catch (e) {
        throw new Error(`Preload script not found: ${PRELOAD_SCRIPT_PATH}`);
    }
}

checkPreloadScript().catch(console.error);

class PluginSystem {
    constructor() {
        this.pluginsPath = path.join(__dirname, 'plugins')
        this.loadedPlugins = new Map()
    }

    // 安全读取插件配置
    async scanPlugins() {
        try {
            console.log(`[DEBUG] 扫描目录: ${this.pluginsPath}`);

            // 递归扫描函数
            const scanDirectory = async (dir) => {
                const plugins = [];
                const pluginInfo = {
                    total: 0,
                    valid: 0,
                    invalid: 0,
                    errors: []
                };

                const entries = await fs.readdir(dir, { withFileTypes: true });
                for (const entry of entries) {
                    const fullPath = path.join(dir, entry.name);
                    console.log("[DEBUG] 扫描到的子目录:", fullPath);

                    if (entry.isDirectory()) {
                        const configPath = path.join(fullPath, "plugin.json");
                        console.log("[DEBUG] 扫描到的plugin:", configPath);

                        try {
                            if (await fs.access(configPath).then(() => true).catch(() => false)) {
                                pluginInfo.total++;
                                const config = JSON.parse(await fs.readFile(configPath, "utf-8"));
                                const requiredFields = ["name", "version", "main"];

                                if (requiredFields.every(field => config[field])) {
                                    const pluginId = `${config.name}@${config.version}`;
                                    const mainModulePath = path.join(fullPath, config.main);

                                    // 验证主文件是否存在
                                    const mainFileExists = await fs.access(mainModulePath)
                                        .then(() => true)
                                        .catch(() => false);

                                    if (mainFileExists) {
                                        plugins.push({
                                            ...config,
                                            path: fullPath,
                                            id: pluginId,
                                            mainModulePath: mainModulePath,
                                            status: 'valid'
                                        });
                                        pluginInfo.valid++;
                                    } else {
                                        pluginInfo.invalid++;
                                        pluginInfo.errors.push({
                                            path: fullPath,
                                            error: `主文件不存在: ${config.main}`
                                        });
                                    }
                                } else {
                                    pluginInfo.invalid++;
                                    pluginInfo.errors.push({
                                        path: fullPath,
                                        error: `缺少必要字段: ${requiredFields.filter(f => !config[f]).join(', ')}`
                                    });
                                }
                            } else {
                                // 递归扫描子目录
                                const subDirResult = await scanDirectory(fullPath);
                                plugins.push(...subDirResult.plugins);
                                pluginInfo.total += subDirResult.pluginInfo.total;
                                pluginInfo.valid += subDirResult.pluginInfo.valid;
                                pluginInfo.invalid += subDirResult.pluginInfo.invalid;
                                pluginInfo.errors.push(...subDirResult.pluginInfo.errors);
                            }
                        } catch (e) {
                            pluginInfo.invalid++;
                            pluginInfo.errors.push({
                                path: fullPath,
                                error: e.message
                            });
                            console.error(`插件加载失败: ${fullPath}`, e);
                        }
                    }
                }

                return { plugins, pluginInfo };
            };

            const { plugins, pluginInfo } = await scanDirectory(this.pluginsPath);

            console.log(`[DEBUG] 扫描结果统计:`, {
                总扫描数: pluginInfo.total,
                有效插件: pluginInfo.valid,
                无效插件: pluginInfo.invalid,
                错误数: pluginInfo.errors.length
            });

            console.log(`[DEBUG] 找到插件:`, plugins.map(p => ({
                id: p.id,
                path: p.path,
                main: p.main,
                mainModulePath: p.mainModulePath
            })));

            return {
                plugins,
                pluginInfo
            };

        } catch (e) {
            console.log("插件扫描失败:", e);
            return {
                plugins: [],
                pluginInfo: {
                    total: 0,
                    valid: 0,
                    invalid: 0,
                    errors: [{
                        path: this.pluginsPath,
                        error: e.message
                    }]
                }
            };
        }
    }

    // 安全加载插件
    async loadPlugins(pluginsArray) {
        const results = [];
        for (const plugin of pluginsArray) {
            try {
                if (this.loadedPlugins.has(plugin.id)) {
                    results.push({ id: plugin.id, success: true, exists: true });
                    continue;
                }
                const module = process.mainModule.require(plugin.mainModulePath);

                // 检查并保存事件处理器
                const eventHandlers = {
                    onBrowserWindowCreated: typeof module.onBrowserWindowCreated === 'function',
                    onLogin: typeof module.onLogin === 'function'
                }

                if (typeof module.init === 'function') {
                    await module.init({ ipcMain, app, BrowserWindow });
                }

                this.loadedPlugins.set(plugin.id, {
                    instance: module,
                    config: plugin,
                    eventHandlers
                });
                results.push({ id: plugin.id, success: true });
            } catch (e) {
                console.info(`插件加载失败: ${plugin.id}`, e);
                results.push({ id: plugin.id, success: false, error: e.message });
            }
        }
        return results;
    }

    triggerBrowserWindowCreated(window) {
        this.loadedPlugins.forEach(plugin => {
            if (plugin.eventHandlers.onBrowserWindowCreated) {
                try {
                    plugin.instance.onBrowserWindowCreated(window);
                } catch (e) {
                    console.error(`[${plugin.id}] onBrowserWindowCreated 执行失败:`, e);
                }
            }
        });
    }

    // 触发用户登录事件
    triggerUserLogin(uid) {
        this.loadedPlugins.forEach(plugin => {
            if (plugin.eventHandlers.onLogin) {
                try {
                    plugin.instance.onLogin(uid);
                } catch (e) {
                    console.error(`[${plugin.id}] onLogin 执行失败:`, e);
                }
            }
        });
    }
}

class WindowManager {
    constructor(config = {}) {
        // 配置项
        this.config = {
            preloadScript: PRELOAD_SCRIPT_PATH, // 默认预加载脚本
            retry: {
                attempts: 3,      // 默认重试次数
                delay: 500       // 重试间隔(ms)
            },
            ...config
        };

        // 核心数据
        this.windows = new Map();         // Map<窗口ID, 窗口元数据>
        this.injectionQueues = new Map(); // Map<窗口ID, Set<脚本路径>>
        this.activeInjections = new Map();// Map<窗口ID, Promise>

        // 自动清理周期
        this.cleanupInterval = setInterval(() => this.cleanup(), 5000);
    }

    /**
     * 注册窗口并开始监控
     * @param {BrowserWindow} win - Electron窗口实例
     */
    track(win) {
        if (this.windows.has(win.id) || win.isDestroyed()) return;

        // 初始化窗口元数据
        const meta = {
            instance: win,
            identifier: this._getWindowIdentifier(win),
            isReady: false,
            lifecycle: 'tracked'
        };

        // 存储元数据
        this.windows.set(win.id, meta);

        // 绑定事件监听
        this._bindWindowEvents(win);
        console.log(`[WindowTracker] 开始监控窗口 ${meta.identifier}`);
    }

    /**
     * 请求脚本注入
     * @param {BrowserWindow} win - 目标窗口
     * @param {string} [scriptPath] - 脚本路径（可选）
     */
    async requestInjection(win, scriptPath) {
        const targetPath = scriptPath || this.config.preloadScript;
        const normalizedPath = this._normalizePath(targetPath);

        // 前置验证
        if (!(await this._validateScriptPath(normalizedPath))) return;
        if (!this.windows.has(win.id)) this.track(win);

        // 判断注入条件
        if (this._isWindowReady(win)) {
            return this._executeInjection(win, normalizedPath);
        }

        // 加入队列
        this._addToQueue(win, normalizedPath);
        console.log(`[Queue] ${this._getWindowIdentifier(win)} 排队脚本: ${path.basename(normalizedPath)}`);
    }

    /*********************
     * 私有方法 *
     *********************/
    _bindWindowEvents(win) {
        // 窗口关闭事件
        const closeHandler = () => {
            console.log(`[WindowLifecycle] 窗口关闭: ${this._getWindowIdentifier(win)}`);
            this._cleanupWindow(win.id);
        };

        // 窗口就绪事件
        const readyHandler = async () => {
            const meta = this.windows.get(win.id);
            meta.isReady = true;
            console.log(`[WindowLifecycle] 窗口就绪: ${meta.identifier}`);
            await this._processQueue(win);
        };

        // 绑定监听
        win.on('closed', closeHandler);
        win.webContents.on('did-finish-load', readyHandler);
    }

    async _processQueue(win) {
        const queue = this.injectionQueues.get(win.id);
        if (!queue || queue.size === 0) return;

        // 创建处理快照
        const tasks = [...queue];
        queue.clear();

        console.log(`[Queue] 开始处理 ${tasks.length} 个脚本 (${this._getWindowIdentifier(win)})`);

        // 顺序执行注入
        for (const scriptPath of tasks) {
            await this._executeWithRetry(
                () => this._executeInjection(win, scriptPath),
                `注入 ${path.basename(scriptPath)}`
            );
        }
    }

    async _executeInjection(win, scriptPath) {
        const meta = this.windows.get(win.id);
        if (!meta || !meta.isReady) return;

        try {
            const content = await this._loadScriptContent(scriptPath);
            await win.webContents.executeJavaScript(content, true);
            console.log(`[Injection] 成功注入到 ${meta.identifier}: ${path.basename(scriptPath)}`);
        } catch (error) {
            console.error(`[InjectionError] ${meta.identifier} 注入失败:`, error.message);
            throw error; // 触发重试
        }
    }

    async _loadScriptContent(scriptPath) {
        const rawContent = await fs.readFile(scriptPath, 'utf8');
        return `
      (function() {
        try {
          ${this._sanitizeScript(rawContent)}
        } catch(e) {
          console.error('[PreloadError]', e);
        }
      })();
    `;
    }

    _sanitizeScript(content) {
        return content
            .replace(/require\(/g, '// require(')
            .replace(/process\./g, '// process.')
            .replace(/__dirname/g, '""')
            .replace(/electron\.remote/g, '// remote');
    }

    async _executeWithRetry(fn, operation) {
        let attempts = this.config.retry.attempts;

        while (attempts > 0) {
            try {
                return await fn();
            } catch (error) {
                attempts--;
                if (attempts === 0) throw error;

                console.warn(`[Retry] ${operation} 剩余尝试次数: ${attempts}`);
                await new Promise(r => setTimeout(r, this.config.retry.delay));
            }
        }
    }

    /*********************
     * 工具方法 *
     *********************/
    _getWindowIdentifier(win) {
        try {
            if (win.isDestroyed()) return `[已销毁] ${win.id}`;
            return win.getTitle() || win.webContents.getURL() || `窗口_${win.id}`;
        } catch (e) {
            return `[未知窗口] ${win.id}`;
        }
    }

    _isWindowReady(win) {
        const meta = this.windows.get(win.id);
        return !!meta && meta.isReady;
    }

    _normalizePath(rawPath) {
        return path.normalize(rawPath).replace(/\\/g, '/');
    }

    async _validateScriptPath(scriptPath) {
        try {
            await fs.access(scriptPath);
            return true;
        } catch (error) {
            console.error(`[路径验证失败] 无法访问脚本: ${scriptPath}`);
            return false;
        }
    }

    _addToQueue(win, scriptPath) {
        if (!this.injectionQueues.has(win.id)) {
            this.injectionQueues.set(win.id, new Set());
        }
        this.injectionQueues.get(win.id).add(scriptPath);
    }

    _cleanupWindow(winId) {
        this.windows.delete(winId);
        this.injectionQueues.delete(winId);
        console.log(`[Cleanup] 已清理窗口 ${winId} 相关数据`);
    }

    cleanup() {
        // 清理已销毁的窗口
        this.windows.forEach((meta, winId) => {
            if (meta.instance.isDestroyed()) {
                this._cleanupWindow(winId);
            }
        });
    }

    /**
     * 销毁管理器
     */
    destroy() {
        clearInterval(this.cleanupInterval);
        this.windows.clear();
        this.injectionQueues.clear();
    }
}

const windowManager = new WindowManager()
const pluginSystem = new PluginSystem()

global.windowManager = windowManager;
global.pluginSystem = pluginSystem;

async function initServer() {
    console.log('[API] 开始扫描插件...');
    const scanResult = await pluginSystem.scanPlugins();
    console.log(`[API] 找到 ${scanResult.plugins.length} 个有效插件`);

    const loadResults = await pluginSystem.loadPlugins(scanResult.plugins);
    const responseData = scanResult.plugins.map(p => {
        const result = loadResults.find(r => r.id === p.id);
        return {
            id: p.id,
            name: p.name,
            desc: p.description || '无描述信息',
            version: p.version,
            author: p.author || '未知作者',
            url: p.repository?.url || '',
            success: result ? result.success : false,
            error: result?.error
        };
    });

    const server = http.createServer(async (req, res) => {
        // 统一 CORS 头配置
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, X-Requested-With',
            'Access-Control-Max-Age': '86400',
            'Content-Type': 'application/json'
        };

        // 处理预检请求
        if (req.method === 'OPTIONS') {
            res.writeHead(204, corsHeaders);
            res.end();
            return;
        }

        // 初始化响应头
        res.writeHead(200, corsHeaders);

        try {
            const parsedUrl = url.parse(req.url, true);

            // 路由处理
            if (parsedUrl.pathname === '/plugins') {
                res.end(JSON.stringify({
                    data: responseData,
                    stats: scanResult.pluginInfo, // 包含扫描统计信息
                    timestamp: Date.now()
                }));

            } else if (parsedUrl.pathname === '/load-plugin' && req.method === 'POST') {
                console.log(`/load-plugin`);
                let body = [];
                req.on('data', chunk => body.push(chunk));
                req.on('end', async () => {
                    try {
                        const { pluginId } = JSON.parse(Buffer.concat(body).toString());
                        console.log(`[API] 收到插件加载请求: ${pluginId}`);

                        const target = (await pluginSystem.scanPlugins()).find(p => p.id === pluginId);

                        if (!target) {
                            console.warn(`[API] 插件未找到: ${pluginId}`);
                            res.writeHead(404, corsHeaders);
                            return res.end(JSON.stringify({
                                error: '插件未找到',
                                pluginId
                            }));
                        }

                        const success = await pluginSystem.loadPlugin(target);
                        console.log(`[API] 插件加载结果: ${pluginId} ${success ? '成功' : '失败'}`);

                        res.writeHead(200, corsHeaders);
                        res.end(JSON.stringify({
                            success,
                            pluginId,
                            timestamp: Date.now()
                        }));

                    } catch (e) {
                        console.error(`[API] 插件加载异常:`, e);
                        res.writeHead(500, corsHeaders);
                        res.end(JSON.stringify({
                            error: e.message,
                            code: 'PLUGIN_LOAD_ERROR'
                        }));
                    }
                });
            } else {
                res.writeHead(404, corsHeaders);
                res.end(JSON.stringify({
                    error: '接口不存在',
                    path: parsedUrl.pathname
                }));
            }

        } catch (e) {
            console.error('[API] 服务器异常:', e);
            res.writeHead(500, corsHeaders);
            res.end(JSON.stringify({
                error: '内部服务器错误',
                code: 'INTERNAL_ERROR',
                timestamp: Date.now()
            }));
        }
    });

    server.on('clientError', (err, socket) => {
        console.error('[API] 客户端错误:', err);
        socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    });

    server.listen(3000, '127.0.0.1', () => {
        console.log('[API] 服务已启动: http://127.0.0.1:3000');
        console.log('[API] 可用接口:');
        console.log('  GET  /plugins       获取插件列表');
    });
}

initServer().catch(e => {
    console.error('[API] 服务初始化失败:', e);
    process.exit(1);
});

app.whenReady().then(() => {
    console.log('[Electron] 已加载插件系统')
    // 监听新窗口创建
    app.on('browser-window-created', (_, win) => {
        windowManager.track(win)

        windowManager.requestInjection(win)
        pluginSystem.triggerBrowserWindowCreated(win); // 触发新窗口事件
    })
}).catch(err => {
    console.log('启动失败:', err);
});