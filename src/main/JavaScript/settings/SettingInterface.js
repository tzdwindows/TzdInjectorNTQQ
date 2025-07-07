// 自定义设置界面类
export class CustomSettingInterface {
    // 私有属性
    #container;
    #navBar;
    #contentArea;
    #panels = new Map(); // 存储所有设置面板 [slug, {navItem, view}]
    #currentSlug = null;

    constructor(containerSelector) {
        // 创建容器元素
        this.#container = document.createElement("div");
        this.#container.className = "custom-settings-container";
        document.querySelector(containerSelector).appendChild(this.#container);

        // 创建导航栏
        this.#navBar = document.createElement("div");
        this.#navBar.className = "settings-nav-bar";
        this.#container.appendChild(this.#navBar);

        // 创建内容区域
        this.#contentArea = document.createElement("div");
        this.#contentArea.className = "settings-content-area";
        this.#container.appendChild(this.#contentArea);

        // 添加默认样式
        this.#addStyles();
    }

    // 添加基础样式
    #addStyles() {
        const style = document.createElement("style");
        style.textContent = `
            .custom-settings-container {
                display: flex;
                height: 100%;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            }
            
            .settings-nav-bar {
                width: 200px;
                background-color: #f5f5f7;
                border-right: 1px solid #e0e0e0;
                overflow-y: auto;
                padding: 15px 0;
            }
            
            .nav-item {
                padding: 10px 20px;
                cursor: pointer;
                transition: background-color 0.2s;
                display: flex;
                align-items: center;
            }
            
            .nav-item:hover {
                background-color: #eaeaea;
            }
            
            .nav-item.active {
                background-color: #d1e0ff;
                font-weight: 500;
            }
            
            .nav-item .icon {
                margin-right: 10px;
                width: 20px;
                height: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .settings-content-area {
                flex: 1;
                padding: 20px;
                overflow-y: auto;
            }
            
            .setting-panel {
                display: none;
            }
            
            .setting-panel.active {
                display: block;
            }
            
            .setting-section {
                margin-bottom: 25px;
                padding-bottom: 15px;
                border-bottom: 1px solid #eee;
            }
            
            .setting-section-title {
                font-size: 18px;
                margin-bottom: 15px;
                color: #333;
            }
            
            .setting-item {
                display: flex;
                align-items: center;
                margin-bottom: 12px;
            }
            
            .setting-label {
                width: 160px;
                margin-right: 15px;
                text-align: right;
                font-size: 14px;
            }
            
            .setting-control {
                flex: 1;
            }
        `;
        document.head.appendChild(style);
    }

    // 添加设置面板
    addPanel(slug, title, iconSvg = null) {
        // 创建导航项
        const navItem = document.createElement("div");
        navItem.className = "nav-item";
        navItem.dataset.slug = slug;

        // 添加图标
        if (iconSvg) {
            const icon = document.createElement("div");
            icon.className = "icon";
            icon.innerHTML = iconSvg;
            navItem.appendChild(icon);
        }

        // 添加标题
        const titleSpan = document.createElement("span");
        titleSpan.textContent = title;
        navItem.appendChild(titleSpan);

        // 点击事件
        navItem.addEventListener("click", () => this.showPanel(slug));

        // 创建内容面板
        const panel = document.createElement("div");
        panel.className = "setting-panel";
        panel.dataset.slug = slug;

        // 添加到DOM
        this.#navBar.appendChild(navItem);
        this.#contentArea.appendChild(panel);

        // 存储引用
        this.#panels.set(slug, { navItem, panel });

        // 如果是第一个面板，设为激活状态
        if (!this.#currentSlug) {
            this.showPanel(slug);
        }

        return panel;
    }

    // 显示指定面板
    showPanel(slug) {
        // 隐藏当前面板
        if (this.#currentSlug) {
            const current = this.#panels.get(this.#currentSlug);
            current.navItem.classList.remove("active");
            current.panel.classList.remove("active");
        }

        // 显示新面板
        const target = this.#panels.get(slug);
        if (target) {
            target.navItem.classList.add("active");
            target.panel.classList.add("active");
            this.#currentSlug = slug;
        }
    }

    // 添加设置项到面板
    addSettingToPanel(slug, settingConfig) {
        const panel = this.#panels.get(slug)?.panel;
        if (!panel) return null;

        const section = document.createElement("div");
        section.className = "setting-section";

        if (settingConfig.title) {
            const title = document.createElement("div");
            title.className = "setting-section-title";
            title.textContent = settingConfig.title;
            section.appendChild(title);
        }

        switch (settingConfig.type) {
            case "switch":
                section.appendChild(this.#createSwitch(settingConfig));
                break;

            case "select":
                section.appendChild(this.#createSelect(settingConfig));
                break;

            case "slider":
                section.appendChild(this.#createSlider(settingConfig));
                break;

            case "button":
                section.appendChild(this.#createButton(settingConfig));
                break;

            case "text":
                section.appendChild(this.#createTextInput(settingConfig));
                break;

            case "color":
                section.appendChild(this.#createColorPicker(settingConfig));
                break;

            case "custom":
                if (settingConfig.content) {
                    section.appendChild(settingConfig.content);
                }
                break;
        }

        panel.appendChild(section);
        return section;
    }

    // 创建开关控件
    #createSwitch(config) {
        const item = document.createElement("div");
        item.className = "setting-item";

        const label = document.createElement("div");
        label.className = "setting-label";
        label.textContent = config.label;
        item.appendChild(label);

        const control = document.createElement("div");
        control.className = "setting-control";

        const switchElem = document.createElement("div");
        switchElem.className = "switch";
        switchElem.innerHTML = `
            <label class="switch-container">
                <input type="checkbox" ${config.value ? "checked" : ""}>
                <span class="slider"></span>
            </label>
        `;

        const input = switchElem.querySelector("input");
        input.addEventListener("change", () => {
            if (config.onChange) {
                config.onChange(input.checked);
            }
        });

        control.appendChild(switchElem);
        item.appendChild(control);
        return item;
    }

    // 创建下拉选择控件
    #createSelect(config) {
        const item = document.createElement("div");
        item.className = "setting-item";

        const label = document.createElement("div");
        label.className = "setting-label";
        label.textContent = config.label;
        item.appendChild(label);

        const control = document.createElement("div");
        control.className = "setting-control";

        const select = document.createElement("select");
        select.className = "setting-select";

        config.options.forEach(option => {
            const optionElem = document.createElement("option");
            optionElem.value = option.value;
            optionElem.textContent = option.label;
            if (option.value === config.value) {
                optionElem.selected = true;
            }
            select.appendChild(optionElem);
        });

        select.addEventListener("change", () => {
            if (config.onChange) {
                config.onChange(select.value);
            }
        });

        control.appendChild(select);
        item.appendChild(control);
        return item;
    }

    // 创建滑块控件
    #createSlider(config) {
        const item = document.createElement("div");
        item.className = "setting-item";

        const label = document.createElement("div");
        label.className = "setting-label";
        label.textContent = config.label;
        item.appendChild(label);

        const control = document.createElement("div");
        control.className = "setting-control";

        const sliderContainer = document.createElement("div");
        sliderContainer.className = "slider-container";

        const slider = document.createElement("input");
        slider.type = "range";
        slider.min = config.min || 0;
        slider.max = config.max || 100;
        slider.step = config.step || 1;
        slider.value = config.value || 50;

        const valueDisplay = document.createElement("span");
        valueDisplay.className = "slider-value";
        valueDisplay.textContent = slider.value;

        slider.addEventListener("input", () => {
            valueDisplay.textContent = slider.value;
            if (config.onChange) {
                config.onChange(Number(slider.value));
            }
        });

        sliderContainer.appendChild(slider);
        sliderContainer.appendChild(valueDisplay);
        control.appendChild(sliderContainer);
        item.appendChild(control);
        return item;
    }

    // 创建按钮控件
    #createButton(config) {
        const item = document.createElement("div");
        item.className = "setting-item";

        // 空标签占位
        const label = document.createElement("div");
        label.className = "setting-label";
        item.appendChild(label);

        const control = document.createElement("div");
        control.className = "setting-control";

        const button = document.createElement("button");
        button.className = "setting-button";
        button.textContent = config.label;

        button.addEventListener("click", () => {
            if (config.onClick) {
                config.onClick();
            }
        });

        control.appendChild(button);
        item.appendChild(control);
        return item;
    }

    // 创建文本输入控件
    #createTextInput(config) {
        const item = document.createElement("div");
        item.className = "setting-item";

        const label = document.createElement("div");
        label.className = "setting-label";
        label.textContent = config.label;
        item.appendChild(label);

        const control = document.createElement("div");
        control.className = "setting-control";

        const input = document.createElement("input");
        input.type = "text";
        input.className = "setting-text-input";
        input.value = config.value || "";
        input.placeholder = config.placeholder || "";

        input.addEventListener("change", () => {
            if (config.onChange) {
                config.onChange(input.value);
            }
        });

        control.appendChild(input);
        item.appendChild(control);
        return item;
    }

    // 创建颜色选择器
    #createColorPicker(config) {
        const item = document.createElement("div");
        item.className = "setting-item";

        const label = document.createElement("div");
        label.className = "setting-label";
        label.textContent = config.label;
        item.appendChild(label);

        const control = document.createElement("div");
        control.className = "setting-control";

        const colorContainer = document.createElement("div");
        colorContainer.className = "color-container";

        const input = document.createElement("input");
        input.type = "color";
        input.value = config.value || "#000000";

        const preview = document.createElement("div");
        preview.className = "color-preview";
        preview.style.backgroundColor = input.value;

        input.addEventListener("input", () => {
            preview.style.backgroundColor = input.value;
            if (config.onChange) {
                config.onChange(input.value);
            }
        });

        colorContainer.appendChild(input);
        colorContainer.appendChild(preview);
        control.appendChild(colorContainer);
        item.appendChild(control);
        return item;
    }
}