'use strict';

const API_ENDPOINT = 'http://127.0.0.1:3000';

const requestConfig = {
    mode: 'cors',
    headers: {
        'Content-Type': 'application/json'
    }
};

const CUSTOM_ERUDA_GLOBAL = 'MyAppDebugger';

async function injectRenamedEruda() {
    // 清理旧脚本
    const existingScript = document.querySelector("#eruda-script");
    if (existingScript) existingScript.remove();

    // 清理可能存在的旧实例
    const existingPanel = document.querySelector(".eruda-dev-tools");
    if (existingPanel) existingPanel.remove();

    // 清理浮动按钮
    const existingButton = document.querySelector(".eruda-entry-btn");
    if (existingButton) existingButton.remove();

    // 如果已存在自定义实例，直接返回
    if (window[CUSTOM_ERUDA_GLOBAL]) return Promise.resolve();

    return new Promise((resolve, reject) => {
        const script = document.createElement("script");
        // 使用固定版本确保稳定性
        script.src = "https://cdn.jsdelivr.net/npm/eruda@2.11.3/eruda.min.js";
        script.id = "eruda-script";

        script.onload = () => {
            try {
                // 确保 eruda 已加载
                if (!window.eruda) {
                    throw new Error("Eruda 未正确加载");
                }

                // 重命名全局变量
                window[CUSTOM_ERUDA_GLOBAL] = window.eruda;
                delete window.eruda; // 删除原始引用

                console.debug("Eruda 已重命名为", CUSTOM_ERUDA_GLOBAL);
                resolve();
            } catch (e) {
                reject(new Error(`重命名失败: ${e.message}`));
            }
        };

        script.onerror = (err) => {
            console.error("Eruda 脚本加载失败", err);
            reject(new Error("Eruda 加载失败"));
        };

        document.head.appendChild(script);
    });
}

async function initCustomEruda() {
    try {
        await injectRenamedEruda();

        if (window[CUSTOM_ERUDA_GLOBAL] && typeof window[CUSTOM_ERUDA_GLOBAL].init === "function") {
            // 初始化Eruda调试工具
            const erudaInstance = window[CUSTOM_ERUDA_GLOBAL].init({
                tool: ['console', 'elements', 'network', 'sources', 'info'],
                autoScale: true,
                defaults: {
                    theme: 'Dark',
                    displaySize: 50
                }
            });

            const debuggerInstance = window[CUSTOM_ERUDA_GLOBAL].get();

            if (debuggerInstance && typeof debuggerInstance.show === "function") {
                debuggerInstance.show();
                console.debug("自定义 Eruda 初始化成功");
                return debuggerInstance;
            } else {
                throw new Error("无法获取 Eruda 实例");
            }
        }

        throw new Error("自定义Eruda初始化函数不可用");
    } catch (error) {
        console.error("自定义 Eruda 初始化失败:", error);

        if (typeof electron !== "undefined" && electron.ipcRenderer) {
            console.warn("尝试使用 Electron 原生开发者工具");
            electron.ipcRenderer.send("open-devtools");
        }

        return null;
    }
}

/** 添加调试窗口 **/
if (document.readyState === "complete" || document.readyState === "interactive") {
    setTimeout(initCustomEruda, 300);
} else {
    document.addEventListener("DOMContentLoaded", () => {
        setTimeout(initCustomEruda, 300);
    });
}

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

let b = false;

function loadHTMLContent(htmlString) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(htmlString, 'text/html');

    // 1. 複製 head 裡的 CSS
    doc.head.querySelectorAll('link[rel="stylesheet"], style').forEach(el => {
        document.head.appendChild(el.cloneNode(true));
    });

    // 2. 複製 body 裡的內容（不含 script）
    doc.body.querySelectorAll(':not(script)').forEach(el => {
        document.body.appendChild(el.cloneNode(true));
    });

    // 3. script 需要「新建」元素才能觸發執行
    doc.querySelectorAll('script').forEach(oldScript => {
        const newScript = document.createElement('script');
        if (oldScript.src) {
            newScript.src = oldScript.src;
        } else {
            newScript.textContent = oldScript.textContent;
        }
        // 保留屬性（例如 type, async, etc.）
        for (const attr of oldScript.attributes) {
            newScript.setAttribute(attr.name, attr.value);
        }
        document.body.appendChild(newScript);
    });
}

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
            if (b) return;

            try {
                loadHTMLContent(`<!doctype html><html lang=en><head><meta charset=UTF-8><link rel=icon type=image/svg+xml href=/vite.svg><meta name=viewport content="width=device-width,initial-scale=1"><title>Vite + Preact + TS</title><script type=module crossorigin>!function(){const e=document.createElement("link").relList;if(!(e&&e.supports&&e.supports("modulepreload"))){for(const e of document.querySelectorAll('link[rel="modulepreload"]'))t(e);new MutationObserver(e=>{for(const _ of e)if("childList"===_.type)for(const e of _.addedNodes)"LINK"===e.tagName&&"modulepreload"===e.rel&&t(e)}).observe(document,{childList:!0,subtree:!0})}function t(e){if(e.ep)return;e.ep=!0;const t=function(e){const t={};return e.integrity&&(t.integrity=e.integrity),e.referrerPolicy&&(t.referrerPolicy=e.referrerPolicy),"use-credentials"===e.crossOrigin?t.credentials="include":"anonymous"===e.crossOrigin?t.credentials="omit":t.credentials="same-origin",t}(e);fetch(e.href,t)}}();var W,h,pe,$,_e,he,de,ve,K,Z,q,N={},me=[],$e=/acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|itera/i,R=Array.isArray;function F(e,t){for(var _ in t)e[_]=t[_];return e}function J(e){e&&e.parentNode&&e.parentNode.removeChild(e)}function He(e,t,_){var n,o,r,l={};for(r in t)"key"==r?n=t[r]:"ref"==r?o=t[r]:l[r]=t[r];if(arguments.length>2&&(l.children=arguments.length>3?W.call(arguments,2):_),"function"==typeof e&&null!=e.defaultProps)for(r in e.defaultProps)void 0===l[r]&&(l[r]=e.defaultProps[r]);return I(e,l,n,o,null)}function I(e,t,_,n,o){var r={type:e,props:t,key:_,ref:n,__k:null,__:null,__b:0,__e:null,__c:null,constructor:void 0,__v:o??++pe,__i:-1,__u:0};return null==o&&null!=h.vnode&&h.vnode(r),r}function L(e){return e.children}function U(e,t){this.props=e,this.context=t}function H(e,t){if(null==t)return e.__?H(e.__,e.__i+1):null;for(var _;t<e.__k.length;t++)if(null!=(_=e.__k[t])&&null!=_.__e)return _.__e;return"function"==typeof e.type?H(e):null}function ye(e){var t,_;if(null!=(e=e.__)&&null!=e.__c){for(e.__e=e.__c.base=null,t=0;t<e.__k.length;t++)if(null!=(_=e.__k[t])&&null!=_.__e){e.__e=e.__c.base=_.__e;break}return ye(e)}}function te(e){(!e.__d&&(e.__d=!0)&&$.push(e)&&!O.__r++||_e!=h.debounceRendering)&&((_e=h.debounceRendering)||he)(O)}function O(){for(var e,t,_,n,o,r,l,i=1;$.length;)$.length>i&&$.sort(de),e=$.shift(),i=$.length,e.__d&&(_=void 0,o=(n=(t=e).__v).__e,r=[],l=[],t.__P&&((_=F({},n)).__v=n.__v+1,h.vnode&&h.vnode(_),Q(t.__P,_,n,t.__n,t.__P.namespaceURI,32&n.__u?[o]:null,r,o??H(n),!!(32&n.__u),l),_.__v=n.__v,_.__.__k[_.__i]=_,ke(r,_,l),_.__e!=o&&ye(_)));O.__r=0}function ge(e,t,_,n,o,r,l,i,c,u,s){var f,a,p,h,d,m,v=n&&n.__k||me,y=t.length;for(c=Me(_,t,v,c,y),f=0;f<y;f++)null!=(p=_.__k[f])&&(a=-1==p.__i?N:v[p.__i]||N,p.__i=f,m=Q(e,p,a,o,r,l,i,c,u,s),h=p.__e,p.ref&&a.ref!=p.ref&&(a.ref&&X(a.ref,null,p),s.push(p.ref,p.__c||h,p)),null==d&&null!=h&&(d=h),4&p.__u||a.__k===p.__k?c=be(p,c,e):"function"==typeof p.type&&void 0!==m?c=m:h&&(c=h.nextSibling),p.__u&=-7);return _.__e=d,c}function Me(e,t,_,n,o){var r,l,i,c,u,s=_.length,f=s,a=0;for(e.__k=new Array(o),r=0;r<o;r++)null!=(l=t[r])&&"boolean"!=typeof l&&"function"!=typeof l?(c=r+a,(l=e.__k[r]="string"==typeof l||"number"==typeof l||"bigint"==typeof l||l.constructor==String?I(null,l,null,null,null):R(l)?I(L,{children:l},null,null,null):null==l.constructor&&l.__b>0?I(l.type,l.props,l.key,l.ref?l.ref:null,l.__v):l).__=e,l.__b=e.__b+1,i=null,-1!=(u=l.__i=Ce(l,_,c,f))&&(f--,(i=_[u])&&(i.__u|=2)),null==i||null==i.__v?(-1==u&&(o>s?a--:o<s&&a++),"function"!=typeof l.type&&(l.__u|=4)):u!=c&&(u==c-1?a--:u==c+1?a++:(u>c?a--:a++,l.__u|=4))):e.__k[r]=null;if(f)for(r=0;r<s;r++)null!=(i=_[r])&&!(2&i.__u)&&(i.__e==n&&(n=H(i)),xe(i,i));return n}function be(e,t,_){var n,o;if("function"==typeof e.type){for(n=e.__k,o=0;n&&o<n.length;o++)n[o]&&(n[o].__=e,t=be(n[o],t,_));return t}e.__e!=t&&(t&&e.type&&!_.contains(t)&&(t=H(e)),_.insertBefore(e.__e,t||null),t=e.__e);do{t=t&&t.nextSibling}while(null!=t&&8==t.nodeType);return t}function Ce(e,t,_,n){var o,r,l=e.key,i=e.type,c=t[_];if(null===c&&null==e.key||c&&l==c.key&&i==c.type&&!(2&c.__u))return _;if(n>(null==c||2&c.__u?0:1))for(o=_-1,r=_+1;o>=0||r<t.length;){if(o>=0){if((c=t[o])&&!(2&c.__u)&&l==c.key&&i==c.type)return o;o--}if(r<t.length){if((c=t[r])&&!(2&c.__u)&&l==c.key&&i==c.type)return r;r++}}return-1}function ne(e,t,_){"-"==t[0]?e.setProperty(t,_??""):e[t]=null==_?"":"number"!=typeof _||$e.test(t)?_:_+"px"}function T(e,t,_,n,o){var r,l;e:if("style"==t)if("string"==typeof _)e.style.cssText=_;else{if("string"==typeof n&&(e.style.cssText=n=""),n)for(t in n)_&&t in _||ne(e.style,t,"");if(_)for(t in _)n&&_[t]==n[t]||ne(e.style,t,_[t])}else if("o"==t[0]&&"n"==t[1])r=t!=(t=t.replace(ve,"$1")),l=t.toLowerCase(),t=l in e||"onFocusOut"==t||"onFocusIn"==t?l.slice(2):t.slice(2),e.l||(e.l={}),e.l[t+r]=_,_?n?_.u=n.u:(_.u=K,e.addEventListener(t,r?q:Z,r)):e.removeEventListener(t,r?q:Z,r);else{if("http://www.w3.org/2000/svg"==o)t=t.replace(/xlink(H|:h)/,"h").replace(/sName$/,"s");else if("width"!=t&&"height"!=t&&"href"!=t&&"list"!=t&&"form"!=t&&"tabIndex"!=t&&"download"!=t&&"rowSpan"!=t&&"colSpan"!=t&&"role"!=t&&"popover"!=t&&t in e)try{e[t]=_??"";break e}catch{}"function"==typeof _||(null==_||!1===_&&"-"!=t[4]?e.removeAttribute(t):e.setAttribute(t,"popover"==t&&1==_?"":_))}}function re(e){return function(t){if(this.l){var _=this.l[t.type+e];if(null==t.t)t.t=K++;else if(t.t<_.u)return;return _(h.event?h.event(t):t)}}}function Q(e,t,_,n,o,r,l,i,c,u){var s,f,a,p,d,m,v,y,g,k,b,w,x,H,P,N,E,M=t.type;if(null!=t.constructor)return null;128&_.__u&&(c=!!(32&_.__u),r=[i=t.__e=_.__e]),(s=h.__b)&&s(t);e:if("function"==typeof M)try{if(y=t.props,g="prototype"in M&&M.prototype.render,k=(s=M.contextType)&&n[s.__c],b=s?k?k.props.value:s.__:n,_.__c?v=(f=t.__c=_.__c).__=f.__E:(g?t.__c=f=new M(y,b):(t.__c=f=new U(y,b),f.constructor=M,f.render=Se),k&&k.sub(f),f.props=y,f.state||(f.state={}),f.context=b,f.__n=n,a=f.__d=!0,f.__h=[],f._sb=[]),g&&null==f.__s&&(f.__s=f.state),g&&null!=M.getDerivedStateFromProps&&(f.__s==f.state&&(f.__s=F({},f.__s)),F(f.__s,M.getDerivedStateFromProps(y,f.__s))),p=f.props,d=f.state,f.__v=t,a)g&&null==M.getDerivedStateFromProps&&null!=f.componentWillMount&&f.componentWillMount(),g&&null!=f.componentDidMount&&f.__h.push(f.componentDidMount);else{if(g&&null==M.getDerivedStateFromProps&&y!==p&&null!=f.componentWillReceiveProps&&f.componentWillReceiveProps(y,b),!f.__e&&null!=f.shouldComponentUpdate&&!1===f.shouldComponentUpdate(y,f.__s,b)||t.__v==_.__v){for(t.__v!=_.__v&&(f.props=y,f.state=f.__s,f.__d=!1),t.__e=_.__e,t.__k=_.__k,t.__k.some(function(e){e&&(e.__=t)}),w=0;w<f._sb.length;w++)f.__h.push(f._sb[w]);f._sb=[],f.__h.length&&l.push(f);break e}null!=f.componentWillUpdate&&f.componentWillUpdate(y,f.__s,b),g&&null!=f.componentDidUpdate&&f.__h.push(function(){f.componentDidUpdate(p,d,m)})}if(f.context=b,f.props=y,f.__P=e,f.__e=!1,x=h.__r,H=0,g){for(f.state=f.__s,f.__d=!1,x&&x(t),s=f.render(f.props,f.state,f.context),P=0;P<f._sb.length;P++)f.__h.push(f._sb[P]);f._sb=[]}else do{f.__d=!1,x&&x(t),s=f.render(f.props,f.state,f.context),f.state=f.__s}while(f.__d&&++H<25);f.state=f.__s,null!=f.getChildContext&&(n=F(F({},n),f.getChildContext())),g&&!a&&null!=f.getSnapshotBeforeUpdate&&(m=f.getSnapshotBeforeUpdate(p,d)),N=s,null!=s&&s.type===L&&null==s.key&&(N=we(s.props.children)),i=ge(e,R(N)?N:[N],t,_,n,o,r,l,i,c,u),f.base=t.__e,t.__u&=-161,f.__h.length&&l.push(f),v&&(f.__E=f.__=null)}catch(e){if(t.__v=null,c||null!=r)if(e.then){for(t.__u|=c?160:128;i&&8==i.nodeType&&i.nextSibling;)i=i.nextSibling;r[r.indexOf(i)]=null,t.__e=i}else for(E=r.length;E--;)J(r[E]);else t.__e=_.__e,t.__k=_.__k;h.__e(e,t,_)}else null==r&&t.__v==_.__v?(t.__k=_.__k,t.__e=_.__e):i=t.__e=Ee(_.__e,t,_,n,o,r,l,c,u);return(s=h.diffed)&&s(t),128&t.__u?void 0:i}function ke(e,t,_){for(var n=0;n<_.length;n++)X(_[n],_[++n],_[++n]);h.__c&&h.__c(t,e),e.some(function(t){try{e=t.__h,t.__h=[],e.some(function(e){e.call(t)})}catch(e){h.__e(e,t.__v)}})}function we(e){return"object"!=typeof e||null==e||e.__b&&e.__b>0?e:R(e)?e.map(we):F({},e)}function Ee(e,t,_,n,o,r,l,i,c){var u,s,f,a,p,d,m,v=_.props,y=t.props,g=t.type;if("svg"==g?o="http://www.w3.org/2000/svg":"math"==g?o="http://www.w3.org/1998/Math/MathML":o||(o="http://www.w3.org/1999/xhtml"),null!=r)for(u=0;u<r.length;u++)if((p=r[u])&&"setAttribute"in p==!!g&&(g?p.localName==g:3==p.nodeType)){e=p,r[u]=null;break}if(null==e){if(null==g)return document.createTextNode(y);e=document.createElementNS(o,g,y.is&&y),i&&(h.__m&&h.__m(t,r),i=!1),r=null}if(null==g)v===y||i&&e.data==y||(e.data=y);else{if(r=r&&W.call(e.childNodes),v=_.props||N,!i&&null!=r)for(v={},u=0;u<e.attributes.length;u++)v[(p=e.attributes[u]).name]=p.value;for(u in v)if(p=v[u],"children"!=u)if("dangerouslySetInnerHTML"==u)f=p;else if(!(u in y)){if("value"==u&&"defaultValue"in y||"checked"==u&&"defaultChecked"in y)continue;T(e,u,null,p,o)}for(u in y)p=y[u],"children"==u?a=p:"dangerouslySetInnerHTML"==u?s=p:"value"==u?d=p:"checked"==u?m=p:i&&"function"!=typeof p||v[u]===p||T(e,u,p,v[u],o);if(s)i||f&&(s.__html==f.__html||s.__html==e.innerHTML)||(e.innerHTML=s.__html),t.__k=[];else if(f&&(e.innerHTML=""),ge("template"==t.type?e.content:e,R(a)?a:[a],t,_,n,"foreignObject"==g?"http://www.w3.org/1999/xhtml":o,r,l,r?r[0]:_.__k&&H(_,0),i,c),null!=r)for(u=r.length;u--;)J(r[u]);i||(u="value","progress"==g&&null==d?e.removeAttribute("value"):null!=d&&(d!==e[u]||"progress"==g&&!d||"option"==g&&d!=v[u])&&T(e,u,d,v[u],o),u="checked",null!=m&&m!=e[u]&&T(e,u,m,v[u],o))}return e}function X(e,t,_){try{if("function"==typeof e){var n="function"==typeof e.__u;n&&e.__u(),n&&null==t||(e.__u=e(t))}else e.current=t}catch(e){h.__e(e,_)}}function xe(e,t,_){var n,o;if(h.unmount&&h.unmount(e),(n=e.ref)&&(n.current&&n.current!=e.__e||X(n,null,t)),null!=(n=e.__c)){if(n.componentWillUnmount)try{n.componentWillUnmount()}catch(e){h.__e(e,t)}n.base=n.__P=null}if(n=e.__k)for(o=0;o<n.length;o++)n[o]&&xe(n[o],t,_||"function"!=typeof e.type);_||J(e.__e),e.__c=e.__=e.__e=void 0}function Se(e,t,_){return this.constructor(e,_)}function Ne(e,t,_){var n,o,r;t==document&&(t=document.documentElement),h.__&&h.__(e,t),n=!1?null:t.__k,o=[],r=[],Q(t,e=t.__k=He(L,null,[e]),n||N,N,t.namespaceURI,n?null:t.firstChild?W.call(t.childNodes):null,o,n?n.__e:t.firstChild,false,r),ke(o,e,r)}W=me.slice,h={__e:function(e,t,_,n){for(var o,r,l;t=t.__;)if((o=t.__c)&&!o.__)try{if((r=o.constructor)&&null!=r.getDerivedStateFromError&&(o.setState(r.getDerivedStateFromError(e)),l=o.__d),null!=o.componentDidCatch&&(o.componentDidCatch(e,n||{}),l=o.__d),l)return o.__E=o}catch(t){e=t}throw e}},pe=0,U.prototype.setState=function(e,t){var _;_=null!=this.__s&&this.__s!=this.state?this.__s:this.__s=F({},this.state),"function"==typeof e&&(e=e(F({},_),this.props)),e&&F(_,e),null!=e&&this.__v&&(t&&this._sb.push(t),te(this))},U.prototype.forceUpdate=function(e){this.__v&&(this.__e=!0,e&&this.__h.push(e),te(this))},U.prototype.render=L,$=[],he="function"==typeof Promise?Promise.prototype.then.bind(Promise.resolve()):setTimeout,de=function(e,t){return e.__v.__b-t.__v.__b},O.__r=0,ve=/(PointerCapture)$|Capture$/i,K=0,Z=re(!1),q=re(!0);var Le=0;function k(e,t,_,n,o,r){t||(t={});var l,i,c=t;if("ref"in c)for(i in c={},t)"ref"==i?l=t[i]:c[i]=t[i];var u={type:e,props:c,key:_,ref:l,__k:null,__:null,__b:0,__e:null,__c:null,constructor:void 0,__v:--Le,__i:-1,__u:0,__source:o,__self:r};if("function"==typeof e&&(l=e.defaultProps))for(i in l)void 0===c[i]&&(c[i]=l[i]);return h.vnode&&h.vnode(u),u}var z,m,V,oe,G=0,Fe=[],y=h,ie=y.__b,le=y.__r,ce=y.diffed,se=y.__c,fe=y.unmount,ae=y.__;function Ae(e,t){y.__h&&y.__h(m,e,G||t),G=0;var _=m.__H||(m.__H={__:[],__h:[]});return e>=_.__.length&&_.__.push({}),_.__[e]}function De(e){return G=1,Te(Pe,e)}function Te(e,t,_){var n=Ae(z++,2);if(n.t=e,!n.__c&&(n.__=[Pe(void 0,t),function(e){var t=n.__N?n.__N[0]:n.__[0],_=n.t(t,e);t!==_&&(n.__N=[_,n.__[1]],n.__c.setState({}))}],n.__c=m,!m.__f)){var o=function(e,t,_){if(!n.__c.__H)return!0;var o=n.__c.__H.__.filter(function(e){return!!e.__c});if(o.every(function(e){return!e.__N}))return!r||r.call(this,e,t,_);var l=n.__c.props!==e;return o.forEach(function(e){if(e.__N){var t=e.__[0];e.__=e.__N,e.__N=void 0,t!==e.__[0]&&(l=!0)}}),r&&r.call(this,e,t,_)||l};m.__f=!0;var r=m.shouldComponentUpdate,l=m.componentWillUpdate;m.componentWillUpdate=function(e,t,_){if(this.__e){var n=r;r=void 0,o(e,t,_),r=n}l&&l.call(this,e,t,_)},m.shouldComponentUpdate=o}return n.__N||n.__}function Ie(){for(var e;e=Fe.shift();)if(e.__P&&e.__H)try{e.__H.__h.forEach(B),e.__H.__h.forEach(Y),e.__H.__h=[]}catch(t){e.__H.__h=[],y.__e(t,e.__v)}}y.__b=function(e){m=null,ie&&ie(e)},y.__=function(e,t){e&&t.__k&&t.__k.__m&&(e.__m=t.__k.__m),ae&&ae(e,t)},y.__r=function(e){le&&le(e),z=0;var t=(m=e.__c).__H;t&&(V===m?(t.__h=[],m.__h=[],t.__.forEach(function(e){e.__N&&(e.__=e.__N),e.u=e.__N=void 0})):(t.__h.forEach(B),t.__h.forEach(Y),t.__h=[],z=0)),V=m},y.diffed=function(e){ce&&ce(e);var t=e.__c;t&&t.__H&&(t.__H.__h.length&&(1!==Fe.push(t)&&oe===y.requestAnimationFrame||((oe=y.requestAnimationFrame)||Ue)(Ie)),t.__H.__.forEach(function(e){e.u&&(e.__H=e.u),e.u=void 0})),V=m=null},y.__c=function(e,t){t.some(function(e){try{e.__h.forEach(B),e.__h=e.__h.filter(function(e){return!e.__||Y(e)})}catch(_){t.some(function(e){e.__h&&(e.__h=[])}),t=[],y.__e(_,e.__v)}}),se&&se(e,t)},y.unmount=function(e){fe&&fe(e);var t,_=e.__c;_&&_.__H&&(_.__H.__.forEach(function(e){try{B(e)}catch(e){t=e}}),_.__H=void 0,t&&y.__e(t,_.__v))};var ue="function"==typeof requestAnimationFrame;function Ue(e){var t,_=function(){clearTimeout(n),ue&&cancelAnimationFrame(t),setTimeout(e)},n=setTimeout(_,35);ue&&(t=requestAnimationFrame(_))}function B(e){var t=m,_=e.__c;"function"==typeof _&&(e.__c=void 0,_()),m=t}function Y(e){var t=m;e.__c=e.__(),m=t}function Pe(e,t){return"function"==typeof t?t(e):t}const Be="data:image/svg+xml,%3csvg%20xmlns='http://www.w3.org/2000/svg'%20xmlns:xlink='http://www.w3.org/1999/xlink'%20aria-hidden='true'%20role='img'%20class='iconify%20iconify--logos'%20width='27.68'%20height='32'%20preserveAspectRatio='xMidYMid%20meet'%20viewBox='0%200%20256%20296'%3e%3cpath%20fill='%23673AB8'%20d='m128%200l128%2073.9v147.8l-128%2073.9L0%20221.7V73.9z'%3e%3c/path%3e%3cpath%20fill='%23FFF'%20d='M34.865%20220.478c17.016%2021.78%2071.095%205.185%20122.15-34.704c51.055-39.888%2080.24-88.345%2063.224-110.126c-17.017-21.78-71.095-5.184-122.15%2034.704c-51.055%2039.89-80.24%2088.346-63.224%20110.126Zm7.27-5.68c-5.644-7.222-3.178-21.402%207.573-39.253c11.322-18.797%2030.541-39.548%2054.06-57.923c23.52-18.375%2048.303-32.004%2069.281-38.442c19.922-6.113%2034.277-5.075%2039.92%202.148c5.644%207.223%203.178%2021.403-7.573%2039.254c-11.322%2018.797-30.541%2039.547-54.06%2057.923c-23.52%2018.375-48.304%2032.004-69.281%2038.441c-19.922%206.114-34.277%205.076-39.92-2.147Z'%3e%3c/path%3e%3cpath%20fill='%23FFF'%20d='M220.239%20220.478c17.017-21.78-12.169-70.237-63.224-110.126C105.96%2070.464%2051.88%2053.868%2034.865%2075.648c-17.017%2021.78%2012.169%2070.238%2063.224%20110.126c51.055%2039.889%20105.133%2056.485%20122.15%2034.704Zm-7.27-5.68c-5.643%207.224-19.998%208.262-39.92%202.148c-20.978-6.437-45.761-20.066-69.28-38.441c-23.52-18.376-42.74-39.126-54.06-57.923c-10.752-17.851-13.218-32.03-7.575-39.254c5.644-7.223%2019.999-8.261%2039.92-2.148c20.978%206.438%2045.762%2020.067%2069.281%2038.442c23.52%2018.375%2042.739%2039.126%2054.06%2057.923c10.752%2017.85%2013.218%2032.03%207.574%2039.254Z'%3e%3c/path%3e%3cpath%20fill='%23FFF'%20d='M127.552%20167.667c10.827%200%2019.603-8.777%2019.603-19.604c0-10.826-8.776-19.603-19.603-19.603c-10.827%200-19.604%208.777-19.604%2019.603c0%2010.827%208.777%2019.604%2019.604%2019.604Z'%3e%3c/path%3e%3c/svg%3e",Oe="data:image/svg+xml,%3csvg%20xmlns='http://www.w3.org/2000/svg'%20xmlns:xlink='http://www.w3.org/1999/xlink'%20aria-hidden='true'%20role='img'%20class='iconify%20iconify--logos'%20width='31.88'%20height='32'%20preserveAspectRatio='xMidYMid%20meet'%20viewBox='0%200%20256%20257'%3e%3cdefs%3e%3clinearGradient%20id='IconifyId1813088fe1fbc01fb466'%20x1='-.828%25'%20x2='57.636%25'%20y1='7.652%25'%20y2='78.411%25'%3e%3cstop%20offset='0%25'%20stop-color='%2341D1FF'%3e%3c/stop%3e%3cstop%20offset='100%25'%20stop-color='%23BD34FE'%3e%3c/stop%3e%3c/linearGradient%3e%3clinearGradient%20id='IconifyId1813088fe1fbc01fb467'%20x1='43.376%25'%20x2='50.316%25'%20y1='2.242%25'%20y2='89.03%25'%3e%3cstop%20offset='0%25'%20stop-color='%23FFEA83'%3e%3c/stop%3e%3cstop%20offset='8.333%25'%20stop-color='%23FFDD35'%3e%3c/stop%3e%3cstop%20offset='100%25'%20stop-color='%23FFA800'%3e%3c/stop%3e%3c/linearGradient%3e%3c/defs%3e%3cpath%20fill='url(%23IconifyId1813088fe1fbc01fb466)'%20d='M255.153%2037.938L134.897%20252.976c-2.483%204.44-8.862%204.466-11.382.048L.875%2037.958c-2.746-4.814%201.371-10.646%206.827-9.67l120.385%2021.517a6.537%206.537%200%200%200%202.322-.004l117.867-21.483c5.438-.991%209.574%204.796%206.877%209.62Z'%3e%3c/path%3e%3cpath%20fill='url(%23IconifyId1813088fe1fbc01fb467)'%20d='M185.432.063L96.44%2017.501a3.268%203.268%200%200%200-2.634%203.014l-5.474%2092.456a3.268%203.268%200%200%200%203.997%203.378l24.777-5.718c2.318-.535%204.413%201.507%203.936%203.838l-7.361%2036.047c-.495%202.426%201.782%204.5%204.151%203.78l15.304-4.649c2.372-.72%204.652%201.36%204.15%203.788l-11.698%2056.621c-.732%203.542%203.979%205.473%205.943%202.437l1.313-2.028l72.516-144.72c1.215-2.423-.88-5.186-3.54-4.672l-25.505%204.922c-2.396.462-4.435-1.77-3.759-4.114l16.646-57.705c.677-2.35-1.37-4.583-3.769-4.113Z'%3e%3c/path%3e%3c/svg%3e";function We(){const[e,t]=De(0);return k(L,{children:[k("div",{children:[k("a",{href:"https://vite.dev",target:"_blank",children:k("img",{src:Oe,class:"logo",alt:"Vite logo"})}),k("a",{href:"https://preactjs.com",target:"_blank",children:k("img",{src:Be,class:"logo preact",alt:"Preact logo"})})]}),k("h1",{children:"Vite + Preact"}),k("div",{class:"card",children:[k("button",{onClick:()=>t(e=>e+1),children:["count is ",e]}),k("p",{children:["Edit ",k("code",{children:"src/app.tsx"})," and save to test HMR"]})]}),k("p",{children:["Check out"," ",k("a",{href:"https://preactjs.com/guide/v10/getting-started#create-a-vite-powered-preact-app",target:"_blank",children:"create-preact"}),", the official Preact + Vite starter"]}),k("p",{class:"read-the-docs",children:"Click on the Vite and Preact logos to learn more"})]})}Ne(k(We,{}),document.getElementById("app"))</script><style rel=stylesheet crossorigin>:root{font-family:system-ui,Avenir,Helvetica,Arial,sans-serif;line-height:1.5;font-weight:400;color-scheme:light dark;color:#ffffffde;background-color:#242424;font-synthesis:none;text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}a{font-weight:500;color:#646cff;text-decoration:inherit}a:hover{color:#535bf2}#root{margin:0;display:flex!important;place-items:center!important;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);max-width:min(90vw,1000px)!important;max-height:min(80vh,700px)!important;z-index:9999999999999999999!important}h1{font-size:3.2em;line-height:1.1}button{border-radius:8px;border:1px solid transparent;padding:.6em 1.2em;font-size:1em;font-weight:500;font-family:inherit;background-color:#1a1a1a;cursor:pointer;transition:border-color .25s}button:hover{border-color:#646cff}button:focus,button:focus-visible{outline:4px auto -webkit-focus-ring-color}@media (prefers-color-scheme:light){:root{color:#213547;background-color:#fff}a:hover{color:#747bff}button{background-color:#f9f9f9}}#app{max-width:1280px;margin:0 auto;padding:2rem;text-align:center}.logo{height:6em;padding:1.5em}.logo:hover{filter:drop-shadow(0 0 2em #646cffaa)}.logo.preact:hover{filter:drop-shadow(0 0 2em #673ab8aa)}.card{padding:2em}.read-the-docs{color:#888}</style></head><body><div id=root><div id=app></div></div></body></html>`);
                b = true;
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
                    tooltip.style.left = `${rect.left + rect.width / 2}px`;
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