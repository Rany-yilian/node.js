# 配置安装与开发调试

## 安装 Git

[Git 官网](https://git-scm.com/downloads)

## 安装 Node

[Node 官网](https://nodejs.org), 支持的最低为 4.0。

## 安装 MySQL

[MySQL 官网](https://www.mysql.com/)


## 项目配置

请修改 [conf.js](../src/conf.js) 文件中的相关配置，详细请参看 [conf.js](../src/conf.js) 中的注释和示例。

> 如果您熟悉项目中使用的 Sequelize 数据库框架，也可以自行安装配置其他类型的数据库。但需要修改 db.js 中相应的 SQL 语句。

## 初始化

项目根目录下执行：

```
node install.js
```

## 设置环境量                       
                                             
Windows   : `set NODE_ENV=development`    
                                         
Mac/Linux : `export NODE_ENV=development`

## 启动服务

```
grunt nodemon
```

## 业务数据配置 (无需求略过)

client_version.json : 配置 SealTalk 移动端的最新 App 版本号、下载地址等信息。

squirrel.json : 配置 SealTalk Desktop 端的最新 App 版本号、下载地址等信息。

demo_square.json : 配置 SealTalk 移动端“发现”频道中的默认聊天室和群组数据。

## 生产环境部署

### 部署文件

项目根目录下执行：

```
grunt release
```

然后将 `dist` 目录拷贝到部署路径即可。

### 修改配置文件

修改 `dist` 目录下 `conf.js` 文件，请根据需要配置,配置项同上述开发环境说明。

### 修改环境变量

生产环境下请设置 `NODE_ENV=production`。

### 启动服务

请在部署路径中用 `PM2` 等工具启动 `index.js` 文件。或直接使用 `node index.js` 启动（不推荐）。
