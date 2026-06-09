# Journey to the West Chapters 1-6 复习互动课

这是给小升初学生复习《Journey to the West》前六章内容的网页课件。当前项目已包含以下章节的互动复习页：

- `Chapter 1: The Monkey（石猴出世）`
- `Chapter 2: Water Curtain Cave（水帘洞）`
- `Chapter 3: Subodhi（菩提祖师）`
- `Chapter 4: Secret Formulas（秘诀）`
- `Chapter 5: The Demon of Chaos（混世魔王）`
- `Chapter 6: The Dragon King（东海龙王）`

主要页面如下：

- `login.html`：登录页
- `chapters.html`：章节选择页
- `index.html`：Chapter 1 复习课件
- `chapter-2.html`：Chapter 2 复习课件
- `chapter-3.html`：Chapter 3 复习课件
- `chapter-4.html`：Chapter 4 复习课件
- `chapter-5.html`：Chapter 5 复习课件
- `chapter-6.html`：Chapter 6 复习课件

另有图片资源、启动脚本和服务端文件。分享时不要只发单个 HTML 文件，否则图片、登录跳转和章节跳转都可能失效。

## 最简单的分享方式

适合：对方只需要本地打开复习，不要求真实 IP 限制。

1. 把整个 `Teaching-English` 文件夹压缩成 zip。
2. 把压缩包发给对方。
3. 对方解压后双击 `start-file-mode.bat`。
4. 页面打开后输入密码：

```text
monkey2026
```

如果 `start-file-mode.bat` 没有自动打开页面，就让对方手动打开同一文件夹里的 `login.html`。

注意：这种方式属于静态文件模式，可以完成基础密码跳转，但不能真正限制“同一个密码最多两个 IP”，因为本地文件模式无法识别真实 IP。

## 局域网分享方式

适合：老师电脑作为主机，学生或其他电脑在同一 Wi-Fi / 局域网访问。

1. 在老师电脑安装 Node.js：[https://nodejs.org/](https://nodejs.org/)
2. 双击 `start-server.bat`。
3. 终端会显示类似地址：

```text
http://localhost:8765/
http://192.168.1.8:8765/
```

4. 老师本机访问 `http://localhost:8765/`
5. 其他设备访问 `http://老师电脑IP:8765/`

示例：

```text
http://192.168.1.8:8765/
```

上课期间不要关闭 `start-server.bat` 对应的终端窗口。

如果其他设备打不开：

- 确认所有设备在同一 Wi-Fi / 局域网。
- 确认使用的是老师电脑的 IP，不是 `localhost`。
- 如果 Windows 防火墙弹窗，允许 Node.js 访问专用网络。
- 如果学校网络禁止设备互访，就需要改用公网部署方式。

## 公网分享方式

适合：对方不在同一个网络，也需要随时访问。

### 方式 A：静态网站

适合：只要求能访问，不要求真实 IP 限制。

把整个项目上传到任意静态站点即可，例如：

- Netlify
- Vercel
- GitHub Pages
- 学校网站空间

上传后从 `login.html` 进入。静态模式下仍然使用本地密码：

```text
monkey2026
```

静态网站不能真正限制 IP，因为没有服务端记录访问来源。

### 方式 B：Node.js 服务端

适合：需要登录态、退出登录和“同一密码最多两个 IP”的限制。

将项目部署到一台公网服务器或支持 Node.js 的托管平台，并运行 `server.js`。例如：

- 云服务器
- Render
- Railway
- Fly.io
- 学校或机构自己的服务器

启动示例：

```powershell
$env:ACCESS_PASSWORD="你的课堂密码"
$env:MAX_IPS_PER_PASSWORD="2"
$env:PORT="8765"
node server.js
```

服务启动后，把公网地址发给学生即可。

## 文件清单

分享时至少保留这些文件：

- `login.html`
- `chapters.html`
- `index.html`
- `chapter-2.html`
- `chapter-3.html`
- `chapter-4.html`
- `chapter-5.html`
- `chapter-6.html`
- `server.js`
- `start-file-mode.bat`
- `start-server.bat`
- `monkey-brand.png`
- `monkey-review-hero.png`
- `chapter-2-hero.png`
- `chapter-3-hero.png`
- `chapter-4-hero.png`
- `chapter-5-hero.png`
- `chapter-6-hero.png`
- `monkey-runner-cute.png`
- `README.md`

`monkey-runner.gif` 是旧图片资源，目前不是必需文件。

## 访问顺序

正常使用顺序如下：

```text
login.html -> chapters.html -> index.html / chapter-2.html / chapter-3.html / chapter-4.html / chapter-5.html / chapter-6.html
```

如果直接打开 `index.html` 或 `chapters.html`，页面会自动跳回 `login.html`。

## 修改密码

### 本地静态模式

当前静态密码写在 `login.html` 中：

```text
monkey2026
```

如果要改静态密码，需要修改 `login.html` 里的对应判断。

### 服务端模式

建议通过环境变量设置密码：

```powershell
$env:ACCESS_PASSWORD="class2026"
$env:MAX_IPS_PER_PASSWORD="2"
$env:PORT="8765"
node server.js
```

## 重置已绑定 IP

服务端模式下，登录记录保存在：

```text
auth-state.json
```

如果需要清空已绑定 IP：

1. 关闭服务端窗口。
2. 删除 `auth-state.json`。
3. 重新运行 `start-server.bat` 或 `node server.js`。

## 课堂使用说明

- 底部 `Previous` / `Next` 用于翻页。
- 顶部 `章节` 返回章节选择页。
- 顶部 `退出` 用于退出登录。
- 词卡、短语卡、关键句和配对页都支持点击互动。
- 音标旁的喇叭使用浏览器语音合成，不依赖外部音频文件。
