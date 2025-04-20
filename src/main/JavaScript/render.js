'use strict';

const API_ENDPOINT = 'http://127.0.0.1:3000';

const requestConfig = {
    mode: 'cors',
    headers: {
        'Content-Type': 'application/json'
    }
};

const safeFetch = async (path, options = {}) => {
    try {
        const startTime = Date.now();
        console.log(`[Network] 请求开始: ${path}`);

        const response = await fetch(`${API_ENDPOINT}${path}`, {
            ...requestConfig,
            ...options,
            credentials: 'include'
        });

        console.log(`[Network] 请求完成: ${path} (${Date.now() - startTime}ms)`);

        if (!response.ok) {
            const error = new Error(`HTTP ${response.status}`);
            error.code = 'HTTP_ERROR';
            throw error;
        }

        return response.json();
    } catch (e) {
        console.log(`[Network] 请求失败: ${path}`, e);
        throw new Error(e.message || '网络连接异常');
    }
};

let response_global

if (typeof window !== 'undefined' && !window.__PRELOAD_INJECTED__) {

    window.__PRELOAD_INJECTED__ = true;

    // 纯名称定位器
    const findElementByName = (targetName) => {
        // 深度遍历整个DOM
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_ELEMENT,
            {
                acceptNode(node) {
                    return NodeFilter.FILTER_ACCEPT;
                }
            },
            false
        );

        // 标准化目标名称（去空格/换行符）
        const normalizedTarget = targetName
            .replace(/\s+/g, '')
            .toLowerCase();

        while (walker.nextNode()) {
            const node = walker.currentNode;

            // 标准化节点文本
            const nodeText = node.textContent
                ?.replace(/\s+/g, '')
                .toLowerCase();

            // 严格匹配（支持部分匹配）
            if (nodeText?.includes(normalizedTarget)) {
                // 验证可见性
                const style = getComputedStyle(node);
                if (style.display !== 'none' && style.visibility !== 'hidden') {
                    return node;
                }
            }
        }
        return null;
    };

    // 查找侧边栏容器（通过已知菜单项名称）
    const findSettingsSidebar = () => {
        const paletteItem = findElementByName('退出账号');
        return paletteItem?.closest('nav, div, ul, ol');
    };

    const createInjectorItem = () => {
        let currentModal = null;

        const safeCreateElement = (tag, styles = {}, children = []) => {
            try {
                const el = document.createElement(tag);
                Object.assign(el.style, styles);
                children.forEach(child => el.appendChild(child));
                return el;
            } catch (e) {
                console.error('[DOM安全操作] 元素创建失败:', e);
                return document.createDocumentFragment();
            }
        };

        const createSettingsWindow = () => {
            if (currentModal) return;

            try {
                // 使用安全方法创建模态窗口
                const modal = safeCreateElement('div', {
                    position: 'fixed',
                    top: '50%',
                    left: '50%',
                    transform: 'translate(-50%, -50%)',
                    width: 'min(90vw, 1000px)',
                    height: 'min(80vh, 700px)',
                    display: 'flex',
                    borderRadius: '16px',
                    overflow: 'hidden',
                    boxShadow: '0 12px 48px rgba(0,0,0,0.3)',
                    background: 'rgba(32, 34, 37, 0.98)',
                    backdropFilter: 'blur(40px)',
                    zIndex: '9999',
                    opacity: '0',
                    transition: 'opacity 0.3s ease'
                });

                // 背景层
                const bgLayer = safeCreateElement('div', {
                    position: 'absolute',
                    top: '0',
                    left: '0',
                    width: '100%',
                    height: '100%',
                    background: 'linear-gradient(45deg, rgba(78, 205, 196, 0.05) 0%, rgba(110, 142, 251, 0.05) 50%, rgba(150, 201, 61, 0.05) 100%)',
                    backdropFilter: 'blur(30px)',
                    zIndex: '-1'
                });

                // 侧边栏
                const sidebar = safeCreateElement('div', {
                    width: '200px',
                    background: 'rgba(255, 255, 255, 0.08)',
                    borderRight: '1px solid rgba(255, 255, 255, 0.1)',
                    padding: '24px 12px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px'
                });

                // 主内容区
                const contentContainer = safeCreateElement('div', {
                    flex: '1',
                    position: 'relative',
                    overflow: 'hidden'
                });

                // 选项卡配置
                const tabs = {
                    main: {
                        label: '仪表盘',
                        icon: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>`,
                        content: createMainContent()
                    },
                    plugins: {
                        label: '插件中心',
                        icon: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>`,
                        content: createPluginContent()
                    },
                    about: {
                        label: '关于',
                        icon: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4m0-4h.01"></path></svg>`,
                        content: createAboutContent()
                    }
                };

                // 创建选项卡按钮
                Object.entries(tabs).forEach(([key, config]) => {
                    const tab = safeCreateElement('div', {
                        borderRadius: '8px',
                        cursor: 'pointer',
                        transition: 'all 0.2s',
                        color: 'rgba(255, 255, 255, 0.9)',
                        marginBottom: '4px'
                    });

                    tab.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 12px; padding: 12px;">
                        ${config.icon}
                        <span style="font-size: 14px; font-weight: 500;">${config.label}</span>
                    </div>
                `;

                    // 安全事件绑定
                    const safeClickHandler = () => {
                        try {
                            switchTab(key);
                        } catch (e) {
                            console.error('[事件处理] 选项卡切换失败:', e.message);
                        }
                    };

                    tab.addEventListener('click', safeClickHandler);
                    sidebar.appendChild(tab);
                });

                // 关闭处理
                const closeModal = () => {
                    try {
                        modal.style.opacity = '0';
                        setTimeout(() => {
                            modal.remove();
                            currentModal = null;
                        }, 300);
                    } catch (e) {
                        console.error('[模态关闭] 操作失败:', e.message);
                    }
                };

                // 关闭按钮
                const closeBtn = safeCreateElement('div', {
                    position: 'absolute',
                    right: '24px',
                    top: '24px',
                    cursor: 'pointer',
                    padding: '8px',
                    borderRadius: '50%',
                    transition: 'all 0.2s',
                    background: 'rgba(255,255,255,0.05)',
                    zIndex: '100'
                });
                closeBtn.innerHTML = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>`;
                closeBtn.addEventListener('click', closeModal);

                // 选项卡切换逻辑
                let activeTab = 'main';
                const switchTab = (tabKey) => {
                    try {
                        if (tabKey === activeTab) return;

                        const oldContent = tabs[activeTab].content;
                        const newContent = tabs[tabKey].content;

                        // 动画过渡
                        oldContent.style.opacity = '0';
                        oldContent.style.transform = 'translateX(-20px)';

                        setTimeout(() => {
                            contentContainer.removeChild(oldContent);
                            contentContainer.appendChild(newContent);

                            newContent.style.display = 'block';
                            newContent.style.opacity = '1';
                            newContent.style.transform = 'translateX(0)';

                            activeTab = tabKey;
                        }, 300);
                    } catch (e) {
                        console.error('[选项卡切换] 操作失败:', e.message);
                    }
                };

                // 初始化内容
                contentContainer.appendChild(tabs.main.content);
                tabs.plugins.content.style.display = 'none';
                tabs.about.content.style.display = 'none';

                // 组装组件
                modal.appendChild(bgLayer);
                modal.appendChild(sidebar);
                modal.appendChild(contentContainer);
                modal.appendChild(closeBtn);
                document.body.appendChild(modal);

                // 启动动画
                requestAnimationFrame(() => modal.style.opacity = '1');
                currentModal = modal;

            } catch (e) {
                console.error('[窗口创建] 致命错误:', e.message);
                // 向QQ日志系统报告错误时避免发送对象
                window?.PerformanceService?.logError?.(e.message || 'Unknown error');
            }
        };

        // 主界面内容生成器
        function createMainContent() {
            const main = document.createElement('div');
            main.style.cssText = `
            position: absolute;
            width: 100%;
            height: 100%;
            transition: all 0.3s ease;
        `;
            main.innerHTML = `
            <div style="text-align: center; padding-top: 80px;">
                <h1 style="
                    font-size: 3em;
                    margin: 40px 0;
                    background: linear-gradient(45deg, #ff6b6b, #4ecdc4, #45b7d1, #96c93d);
                    -webkit-background-clip: text;
                    background-clip: text;
                    color: transparent;
                    animation: flow 8s ease infinite;
                    background-size: 300% 300%;
                ">TzdInjectorNTQQ</h1>
                <p style="color: var(--text-secondary); margin-bottom: 8px;">版本 1.0.0</p>
                <p style="color: var(--text-secondary); margin-bottom: 20px;">作者：tzdwindows 7</p>
                <p style="
                    max-width: 600px;
                    margin: 0 auto;
                    color: var(--text-primary);
                    line-height: 1.6;
                ">基于Electron架构实现的QQ客户端JavaScript执行环境控制工具，提供动态代码注入、消息监控和调试控制能力。</p>
            </div>
        `;
            return main;
        }

        // 插件内容生成器
        function createPluginContent() {
            const plugins = document.createElement('div');
            plugins.style.cssText = `
        position: absolute;
        width: 100%;
        height: 100%;
        padding: 24px;
        box-sizing: border-box;
        overflow: hidden;
        display: flex;
        flex-direction: column;
    `;

            plugins.innerHTML = `
    <div style="
        flex: 1;
        display: flex;
        flex-direction: column;
        overflow: hidden;
        min-width: 0;  /* 关键修复：允许内容收缩 */
    ">
        <h2 style="
            margin:0 0 16px; 
            font-size: 18px;
            font-weight: 600;
            color: rgba(255,255,255,0.9);
            display: flex;
            align-items: center;
            gap: 8px;
        ">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                <circle cx="12" cy="7" r="4"></circle>
            </svg>
            插件管理中心
        </h2>
        
        <div style="
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
            border: 1px solid rgba(255,255,255,0.08);
            overflow: hidden;
            flex: 1;
            display: flex;
            flex-direction: column;
            min-width: 0;  /* 关键修复 */
        ">
            <!-- 表头 -->
            <div style="
                background: rgba(78,205,196,0.08);
                padding: 12px 16px;
                border-bottom: 1px solid rgba(255,255,255,0.05);
                position: sticky;
                top: 0;
                z-index: 1;
            ">
                <div class="grid-header" style="
                    display: grid;
                    grid-template-columns: 
                        minmax(120px, 2fr) 
                        minmax(160px, 3fr) 
                        minmax(60px, 1fr) 
                        minmax(90px, 1fr) 
                        minmax(80px, 1fr);
                    gap: 8px;
                    color: rgba(255,255,255,0.6);
                    font-size: 12px;
                    font-weight: 500;
                ">
                    <div>插件名称</div>
                    <div>功能描述</div>
                    <div style="text-align:center">版本</div>
                    <div style="text-align:center">开发者</div>
                    <div style="text-align:right">状态</div>
                </div>
            </div>
            
            <!-- 内容区域 -->
            <div id="plugin-list" style="
                flex: 1;
                overflow-y: auto;
                padding: 0 16px;
                scroll-behavior: smooth;
            ">
                <div class="loading-container">
                    <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" 
                        style="animation: spin 1s linear infinite">
                        <path d="M12 2v4m0 12v4m-8-8H2m20 0h-4" stroke-linecap="round"/>
                        <circle cx="12" cy="12" r="4" stroke-width="2"/>
                    </svg>
                    <div style="font-size: 13px">正在加载插件列表...</div>
                </div>
            </div>
        </div>
    </div>
    `;

            // 添加样式表
            const style = document.createElement('style');
            style.textContent = `
        .plugin-row {
            display: grid;
            grid-template-columns: 
                minmax(120px, 2fr) 
                minmax(160px, 3fr) 
                minmax(60px, 1fr) 
                minmax(90px, 1fr) 
                minmax(80px, 1fr);
            gap: 8px;
            font-size: 12px;
            padding: 10px 0;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            align-items: center;
            min-width: 0;  /* 关键修复 */
        }

        .plugin-row > div {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            padding: 0 4px;
            min-width: 0;  /* 允许内容收缩 */
        }

        .desc-cell {
    position: relative;  /* 创建定位上下文 */
}

        .desc-tooltip {
    visibility: hidden;
    position: fixed;     /* 改为fixed定位 */
    background: rgba(0,0,0,0.95);
    color: #fff;
    padding: 12px;
    border-radius: 8px;
    font-size: 12px;
    max-width: 400px;
    width: max-content;
    z-index: 1000;
    pointer-events: none;
    opacity: 0;
    transition: opacity 0.2s;
    backdrop-filter: blur(4px);
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    white-space: normal;
    line-height: 1.5;
    text-align: left;

    /* 添加小箭头 */
    &::after {
        content: '';
        position: absolute;
        left: 50%;
        transform: translateX(-50%);
        border: 6px solid transparent;
        border-top-color: rgba(0,0,0,0.95);
        top: 100%;
    }
}

.desc-cell:hover .desc-tooltip {
    visibility: visible;
    opacity: 1;
}

        @keyframes spin {
            100% { transform: rotate(360deg); }
        }

        #plugin-list::-webkit-scrollbar {
            width: 6px;
            background: rgba(0,0,0,0.1);
        }

        #plugin-list::-webkit-scrollbar-thumb {
            background: rgba(255,255,255,0.2);
            border-radius: 3px;
        }
    `;
            plugins.appendChild(style);

            // 插件加载逻辑
            const loadPluginData = async () => {
                try {
                    const container = plugins.querySelector('#plugin-list');
                    container.innerHTML = '';

                    response_global.data.forEach(p => {
                        const row = document.createElement('div');
                        row.className = 'plugin-row';
                        row.innerHTML = `
                <div>${p.name}</div>
                <div class="desc-cell">
                    <span>${p.desc}</span>
                    <div class="desc-tooltip">${p.desc}</div>
                </div>
                <div style="text-align:center">${p.version}</div>
                <div style="text-align:center">${p.author}</div>
                <div style="text-align:right;color:${p.success ? '#4ecdc4' : '#ff6b6b'}">
                    ${p.success ? '✓' : '✗'}
                </div>
            `;

                        // 获取相关元素
                        const descCell = row.querySelector('.desc-cell');
                        const tooltip = row.querySelector('.desc-tooltip');

                        // 新的定位逻辑
                        descCell.addEventListener('mousemove', (e) => {
                            // 获取单元格的位置信息
                            const cellRect = descCell.getBoundingClientRect();
                            const tooltipWidth = tooltip.offsetWidth;
                            const tooltipHeight = tooltip.offsetHeight;

                            // 计算垂直位置（显示在单元格上方）
                            let posY = cellRect.top - tooltipHeight - 8;

                            // 如果上方空间不足则显示在下方
                            if (posY < 20) {
                                posY = cellRect.bottom + 8;
                            }

                            // 计算水平位置（居中于单元格）
                            let posX = cellRect.left + (cellRect.width / 2) - (tooltipWidth / 2);

                            // 边界保护
                            posX = Math.max(20, Math.min(posX, window.innerWidth - tooltipWidth - 20));

                            // 应用定位
                            tooltip.style.left = `${posX - 240}px`;
                            tooltip.style.top = `${posY - 50}px`;
                        });

                        container.appendChild(row);
                    });

                } catch (e) {
                    container.innerHTML = `
            <div class="plugin-row" style="color:#ff6b6b;grid-column:1/-1;text-align:center;padding:16px 0">
                ${e.message || '数据加载失败'}
            </div>`;
                }
            };


            // 启动加载
            setTimeout(() => loadPluginData(), 100);

            plugins.querySelector('#plugin-list').addEventListener('mousemove', (e) => {
                const tooltip = e.target.closest('.desc-text')?.nextElementSibling;
                if (tooltip && tooltip.classList.contains('desc-tooltip')) {
                    const rect = tooltip.parentElement.getBoundingClientRect();
                    tooltip.style.left = `${rect.left + rect.width/2}px`;
                    tooltip.style.bottom = `${window.innerHeight - rect.top + 8}px`;
                }
            });

            return plugins;
        }

        // 关于内容生成器
        function createAboutContent() {
            const about = document.createElement('div');
            about.style.cssText = `
        position: absolute;
        width: 100%;
        height: 100%;
        padding: 32px;
        opacity: 0;
        transform: translateX(20px);
        transition: all 0.3s ease;
        box-sizing: border-box;
        color: rgba(255,255,255,0.85);
    `;

            about.innerHTML = `
         <div style="
        max-width: 800px;
        margin: 0 auto;
        font-family: 'Segoe UI', system-ui, sans-serif;
        height: 100%;
        display: flex;
        flex-direction: column;
    ">
        <div style="
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 32px;
        ">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
            </svg>
            <h1 style="
                margin: 0;
                font-size: 24px;
                font-weight: 600;
                background: linear-gradient(120deg, #6e8efb, #4ecdc4);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            ">
                TzdInjectorNTQQ 技术档案
            </h1>
        </div>

        <div style="
            flex: 1;
            overflow-y: auto;
            scroll-behavior: smooth;
            padding-right: 8px;
        ">
                <div style="
                    background: rgba(255,255,255,0.03);
                    padding: 24px;
                    border-radius: 12px;
                    border: 1px solid rgba(110,142,251,0.15);
                ">
                    <h3 style="
                        margin: 0 0 16px;
                        font-size: 18px;
                        color: #6e8efb;
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    ">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <circle cx="12" cy="12" r="2"></circle>
                            <path d="M16 8v4m0 0v4m0-4h4m-4 0H8m8 8l3 3M8 16l-3 3m3-13L8 3m8 5l3-3"/>
                        </svg>
                        核心技术栈
                    </h3>
                    <ul style="
                        list-style: none;
                        padding: 0;
                        margin: 0;
                        display: grid;
                        gap: 12px;
                    ">
                        ${['V8 引擎运行时注入', 'IPC 通信劫持', '模块热替换 (HMR)', '安全沙箱机制'].map(text => `
                            <li style="
                                display: flex;
                                align-items: center;
                                gap: 8px;
                                padding: 8px 12px;
                                background: rgba(110,142,251,0.08);
                                border-radius: 6px;
                            ">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                    <path d="M20 6L9 17l-5-5"/>
                                </svg>
                                ${text}
                            </li>
                        `).join('')}
                    </ul>
                </div>

                <div style="
                    background: rgba(255,255,255,0.03);
                    padding: 24px;
                    border-radius: 12px;
                    border: 1px solid rgba(78,205,196,0.15);
                ">
                    <h3 style="
                        margin: 0 0 16px;
                        font-size: 18px;
                        color: #4ecdc4;
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    ">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <path d="M12 2v20M2 12h20"/>
                        </svg>
                        性能指标
                    </h3>
                    <div style="display: grid; gap: 16px;">
                        ${[
                { label: '注入延迟', value: '<3ms', color: '#6e8efb' },
                { label: '内存占用', value: '<16MB', color: '#4ecdc4' },
                { label: '启动时间', value: '0.2s', color: '#96c93d' }
            ].map(item => `
                            <div style="
                                background: rgba(255,255,255,0.03);
                                padding: 12px;
                                border-radius: 8px;
                                border-left: 4px solid ${item.color};
                            ">
                                <div style="
                                    display: flex;
                                    justify-content: space-between;
                                    margin-bottom: 6px;
                                    font-size: 14px;
                                    color: rgba(255,255,255,0.7);
                                ">
                                    <span>${item.label}</span>
                                    <span style="color: ${item.color}">${item.value}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>

            <div style="
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 16px;
                background: rgba(255,255,255,0.02);
                border-radius: 8px;
                font-size: 14px;
            ">
                <div>开源协议：MIT License</div>
                <div style="color: rgba(255,255,255,0.6)">
                    编译版本：${new Date().toLocaleDateString('zh-CN', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit'
            })}
                </div>
            </div>
        </div>
    `;

            const style = document.createElement('style');
            style.textContent = `
        #plugin-scroll-container::-webkit-scrollbar {
            width: 8px;
            background: rgba(0,0,0,0.1);
        }
        #plugin-scroll-container::-webkit-scrollbar-thumb {
            background: rgba(255,255,255,0.2);
            border-radius: 4px;
        }
    `;
            about.appendChild(style);
            return about;
        }

        // 创建入口项目
        const item = safeCreateElement('div');
        item.innerHTML = `
        <style>
            .tzd-inject-item {
                padding: 12px 20px;
                margin: 6px 0;
                cursor: pointer;
                transition: all 0.25s ease;
                border-radius: 8px;
                background: rgba(110, 142, 251, 0.1);
                position: relative;
            }
            .tzd-inject-item:hover {
                background: rgba(110, 142, 251, 0.2);
                transform: translateX(5px);
            }
        </style>
        <div class="tzd-inject-item">
            <span style="display: flex; align-items: center; gap: 8px;">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
                </svg>
                TzdInjectorNTQQ
            </span>
        </div>
    `;

        // 安全事件绑定
        const safeClickHandler = (e) => {
            try {
                e.stopPropagation();
                createSettingsWindow();
            } catch (err) {
                console.error('[入口点击] 事件处理失败:', err.message);
            }
        };

        item.querySelector('.tzd-inject-item').addEventListener('click', safeClickHandler);
        return item;
    };

    // 执行注入流程
    const performInjection = () => {
        try {
            const sidebar = findSettingsSidebar();
            if (!sidebar) return;
            const existing = Array.from(sidebar.children).find(child =>
                child.textContent?.includes('TzdInjectorNTQQ')
            );
            if (existing) return;

            async function init() {
                response_global = await safeFetch('/plugins');
            }
            init();
            const injectItem = createInjectorItem();
            const settingPos = Array.from(sidebar.children).findIndex(child =>
                child.textContent?.replace(/\s+/g, '').includes('设置')
            );
            if (settingPos !== -1) {
                sidebar.insertBefore(injectItem, sidebar.children[settingPos]);
            } else {
                sidebar.appendChild(injectItem);
            }
        } catch (err) {
            console.error('注入失败:', err);
        }
    };

    // 自适应注入策略
    const autoInject = () => {
        // 立即尝试
        performInjection();

        // 周期性检查（10秒内尝试5次）
        let retryCount = 0;
        const retryInterval = setInterval(() => {
            if (retryCount++ >= 4) clearInterval(retryInterval);
            performInjection();
        }, 2000);
    };

    // DOM就绪后启动
    if (document.readyState === 'complete') {
        autoInject();
    } else {
        document.addEventListener('DOMContentLoaded', autoInject);
    }

    // 动态内容监听
    new MutationObserver((mutations) => {
        mutations.forEach(mutation => {
            if (mutation.addedNodes.length > 0) {
                performInjection();
            }
        });
    }).observe(document.body, {
        childList: true,
        subtree: true
    });

} else {
    console.log('环境检查未通过');
}