# Satisfactory Server Starter

幸福工厂服务器启动器 - 用于 SteamService 环境下的 Satisfactory 专用服务器启动脚本。

## 功能特性

- 自动安装/更新 Satisfactory 服务器
- 支持自定义端口配置
- 支持 Supervisor 守护进程管理
- 自动处理文件权限
- 支持重试机制应对网络问题
- 内置 Banner 显示

## 构建

### 本地构建

```bash
# 构建 Linux amd64
make build

# 构建所有平台
make build-all

# 压缩二进制文件 (需要 upx)
make compress

# 清理构建产物
make clean
```

### 使用 Docker

```bash
docker run --rm -v $(pwd):/app -w /app golang:1.22 go build -trimpath -buildvcs=false -tags netgo -ldflags="-s -w" -o satisfactory-simpfun-for-steamservice-start-script .
```

## 配置

程序启动时会在用户主目录下创建 `start.ini` 配置文件。

### 配置项说明

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `appId` | 1690800 | Steam 应用 ID (不要修改) |
| `os` | linux | 操作系统类型 |
| `port.enabled` | false | 是否自定义游戏数据端口 |
| `port.value` | 7777 | 游戏数据端口 |
| `query_port.enabled` | false | 是否自定义查询端口 |
| `query_port.value` | 15777 | 查询端口 |
| `beacon_port.enabled` | false | 是否自定义信标端口 |
| `beacon_port.value` | 15000 | 信标端口 |
| `log.enabled` | true | 启用服务器日志 |
| `unattended.enabled` | true | 无人值守模式 |
| `nocrashdialog.enabled` | true | 禁用崩溃对话框 |
| `multihome.enabled` | false | 绑定主机 IP |
| `multihome.value` | | 主机 IP |
| `skip_install` | false | 跳过安装/更新 |
| `install_retry_forever` | true | 无限重试安装 |
| `install_retry_interval` | 10s | 重试间隔 |
| `supervisor_enabled` | false | 启用 Supervisor |
| `supervisor_socket` | | Supervisor Unix 套接字 |
| `supervisor_program` | satisfactory | Supervisor 程序名称 |
| `supervisor_conf_path` | | Supervisor 配置文件路径 |
| `banner_path` | banner.txt | Banner 文件路径 |
| `banner_wait` | 5s | Banner 显示时间 |
| `start_user` | container | 运行用户 |
| `chown_install_dir` | true | 自动修改目录所有者 |
| `chmod_install_dir` | true | 自动修改目录权限 |

### 环境变量

所有配置项都可以通过环境变量覆盖，例如：

- `SATISFACTORY_APP_ID` - 应用 ID
- `SATISFACTORY_INSTALL_DIR` - 安装目录
- `SATISFACTORY_SKIP_INSTALL` - 跳过安装
- `STEAMSERVICE_UNIX_SOCKET_PATH` - SteamService Unix 套接字路径

## 使用

### 端口配置

服务器至少需要配置 2 个端口：

1. **游戏数据端口** (port) - 必须
2. **信标端口** (beacon_port) - 必须
3. **查询端口** (query_port) - 建议

### 关闭服务器

在控制台输入 `stop` 即可正常关闭服务器。

### 存档位置

```
/home/container/.config/Epic/FactoryGame/Saved/SaveGames
```

## GitHub Actions CI

项目配置了 GitHub Actions 自动构建：

- 推送到 `master`/`main` 分支时自动构建
- 创建 `v*` 标签时自动发布 Release
- 支持 Linux amd64 和 arm64 架构
- 使用 UPX 压缩二进制文件

### 发布流程

```bash
git tag v1.0.0
git push origin v1.0.0
```

## 许可证

[MIT License](LICENSE)

## 交流群

QQ群: 949671297
