# Frida 使用指导

## 1. Frida概况
- frida 是一个 hook 框架  
    * 可以在不改动目标源码的情况下，动态查看函数运行入参，返回值，注入代码，更程序逻辑。  
    * 黑客可以用hook框架做逆向，分析和利用应用漏洞，进行非法操作。  
    * 开发者可以hook自己的应用进程，查看API接口入参，返回值。如果应用出现问题可以通过此方法打印信息，不需要额外增加日志，简单方便。  
    * hook代码使用 js 脚本实现，借助 python 执行（也可以使用C, Node.js, Swift, .NET等等）。
- 覆盖平台：Android, iOS, Windows, Linux， OSX
- 覆盖语言： c/c++, Java, Object-C  
-  优势  
    * 覆盖平台广；  
    * 采用google v8 engine,较为稳定（Android 需要使用Google原生系统）；  
    * 更新hook代码，不需要重启系统（安卓常用的xposed框架，iOS常用的Cydiasbustrate, hook插件更新，需要重启系统）；  
    * 对于手机应用 hook，即使不 root(jailbreak)，也提供了方案，其他常用的如 xposed（Android）和Cydia substrate（iOS，Android）是不行的。


## 2. 安装 & 环境配置
分为pc端的环境和移动端的frida-server进程（如果是用于手机端的hook）。

- PC端  
> install Python 3.x  
pip install frida  
pip install frida-tools  

安装测试， 命令行执行 frida-ps，输出系统运行的所有进程及pid
- 移动端  
    *  Android   
先root， 再配置 frida-server （下载并push到/data/tmp/local, 以root权限执行， 下载地址 https://github.com/frida/frida/releases）  
    * iOS   
    先 jailbreak，再从cydia下载frida插件。  
    * 如果没法root或越狱，可简单的修改应用，在应用初始化时，主动加载frida组件，相当于进程内部hook。详见：https://frida.re/docs/gadget/ （强烈建议设备root或越狱）    

安装测试， 命令行执行 frida-ps -U，输出系统运行的所有进程及pid


## 3. frida 具体用法

hook最终使用 js 脚本，而脚本是通过外部环境和frida-core交互，这里使用python作为外部环境。
#### (a) hook脚本模板（python代码）

```
########################### main.py ###########################
import frida, sys, os
import traceback

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])

def hook(proc_name, target_js):
    print('proc name ='+proc_name)
    with open(target_js) as fin:
        script_source = fin.read()

    process = frida.get_usb_device().attach(proc_name)
    script = process.create_script(script_source)
    script.on('message', on_message)
    script.load()

    try:
        while True:
            if sys.stdin.read().strip() == 'stop':
                print('Get stop signial, and going to clean frida.')
                script.unload()
                process.detach()
                break
    except Exception:
        script.unload()
        process.detach()
        traceback.print_exc()


if __name__ == "__main__":
    js_dir = os.path.dirname(os.path.realpath(__file__))
    # 将 js 放入单独的文件，便于写代码，检查js语法，此外还可模块化管理脚本
    target_js = os.path.join(js_dir, 'scripts', 'libc.js')
    hook("processname",  target_js)
    
    
########################### scripts/libc.js ###########################
try {
    Interceptor.attach(Module.findExportByName("libc.so", "strlen"), {
        onEnter: function(args) {
            console.log("in strlen, arg0="+Memory.readUtf8String(args[0]));
        },
    });
    
}catch(err) {
    console.log("err:"+err);
}
```

#### (b) 常见hook操作示例
frida hook，这里使用 python 代码 + js 脚本（也可直接使用c，Node.js等），由浅入深介绍frida hook 函数的基本用法用法，包括：打印、更改入参和返回值；调用其他函数；注入字符串；注入对象（结构体）。  
*注：除最后一个例子外，均采用官网用例，基于linux, C代码，所有例子均为完整代码，可以直接编译演示*
##### Example 1 hook 函数并打印入参
```
########################### hello.c ###########################
#include <stdio.h>
#include <unistd.h>

void f (int n)
{
  printf ("Number: %d\n", n);
}

int main (int argc, char * argv[])
{
  int i = 0;
  /* 打印目标函数地址。对于第三方库函数，可以通过解析符号表得到函数地址。*/
  printf ("f() is at %p\n", f);  
  while (1)
  {
    f (i++);
    sleep (1);
  }
}
########################### hook.py ###########################
from __future__ import print_function
import frida
import sys

session = frida.attach("hello")
script = session.create_script("""
Interceptor.attach(ptr("%s"), {
    onEnter: function(args) {
        send(args[0].toInt32());
    }
});
""" % int(sys.argv[1], 16))
def on_message(message, data):
    print(message)
script.on('message', on_message)
script.load()
sys.stdin.read()
```
> gcc  hello.c -o hello  
./hello    

输出：  
```
f() is at 0x400544（目标函数地址）  
Number: 0  
Number: 1  
Number: 2  
```
  
>python hook.py $目标函数地址 (目标函数地址，需要填入实际值)  

输出：  

```
{u'type': u'send', u'payload': 531}  
{u'type': u'send', u'payload': 532}  
… 
```
##### Example 2 修改函数入参

```
########################### modify.py ###########################
import frida
import sys

session = frida.attach("hello")
script = session.create_script("""
Interceptor.attach(ptr("%s"), {
    onEnter: function(args) {
        args[0] = ptr("1337");  #将入参修改为恒定的1337
    }
});
""" % int(sys.argv[1], 16))
script.load()
sys.stdin.read()
```
> python modify.py 0x400544  

输出：  

```
Number: 1281
Number: 1282  
Number: 1337  
Number: 1337  
Number: 1337  
…
```

##### Example 3 调用函数

```
########################### call.py ###########################
import frida
import sys

session = frida.attach("hello")
script = session.create_script("""
var f = new NativeFunction(ptr("%s"), 'void', ['int']);
f(1911);
f(1911);
f(1911);
""" % int(sys.argv[1], 16))
script.load()
```

>  python call.py 0x400544  

输出：  
```
Number: 1879  
Number: 1911  
Number: 1911  
Number: 1911  
Number: 1880  
…
```

##### Example 4 构造字符串（char*）

```
########################### hi.c ###########################
#include <stdio.h>
#include <unistd.h>
int f (const char * s)
{
  printf ("String: %s\n", s);
  return 0;
}

int main (int argc, char * argv[])
{
  const char * s = "Testing!";
  printf ("f() is at %p\n", f);
  printf ("s is at %p\n", s);

  while (1)
  {
    f (s);
    sleep (1);
  }
}

########################### stringhook.py ###########################
from __future__ import print_function
import frida
import sys

session = frida.attach("hi")
script = session.create_script("""
# 在目标进程的内存 构造字符串
var st = Memory.allocUtf8String("TESTMEPLZ!");
# NativeFunction入参分别为 函数地址，返回值， 入参列表
var f = new NativeFunction(ptr("%s"), 'int', ['pointer']);
f(st);
""" % int(sys.argv[1], 16))
def on_message(message, data):
    print(message)
script.on('message', on_message)
script.load()
```
输出：  

```
String: Testing!  
String: Testing!  
String: TESTMEPLZ!  
String: Testing!  
```




##### Example 5 构造结构体（struct*）
frida 官网给出了socket 的用例，稍微有点复杂。这里换个例子，新建一个动态库，动态库定义一个结构体 mystruct 和一个通过结构体指针打印结构体数据的函数 print_struct ，main函数调用print_struct 。


```
########################### so.h ###########################
#include <stdio.h>

struct mystruct {
    int ival1;
    int ival2;
};
void print_struct(void *para);

########################### so.c ###########################
#include "so.h"

void print_struct(void* para) {
    struct mystruct *ptr = (struct mystruct*) para;
    printf("ival1:%d, ival2:%d\n", ptr->ival1, ptr->ival2);
}


########################### main.c ###########################
#include "so.h"
#include <unistd.h>

int main(int argc, char* argv[]) {
    struct mystruct s;
    s.ival1 = 1;
    s.ival2 = 2;
    
    while(1){
        print_struct(&s);
        sleep(2);
    }
    
    return 0;
}

########################### inject_struct.py ###########################
from __future__ import print_function
import frida
import sys

session = frida.attach("main")
script = session.create_script("""

try {
    # 在目标进程分配内存，并根据strcut数据在内存的分布，按字节写入数据
    var st = Memory.alloc(8);
    st.writeByteArray([6, 0, 0, 0, 4, 0, 0, 0]);
    Interceptor.attach(Module.getExportByName(null, "print_struct"), {
        onEnter: function(args) {
            console.log('in print_struct');
            args[0] = st;
        },
    });
}catch(err) {
    console.log("err:"+err+", trace"+err.stack);
}  """)

def on_message(message, data):
    print(message)

script.on('message', on_message)
script.load()
sys.stdin.read()
```
编译动态库:
> gcc -shared -fPIC -o libtest.so so.c

编译main：
> gcc -o main main.c libtest.so

运行main：
> ./main  

输出：  
```
ival1:1, ival2:2  
ival1:1, ival2:2  
ival1:1, ival2:2  
...
```
执行:
> python inject_struct.py  

输出：  
```
...  
ival1:1, ival2:2  
ival1:1, ival2:2  
ival1:1, ival2:2  
ival1:6, ival2:4  
ival1:6, ival2:4  
...
```
##### Example 6 构造其他参数对象
这里不另外举例，与上个例子类似，简单说下思路：  根据内存分布，找到目标数据地址，直接往地址读写数据即可。对于只读内存区域无法写入。


#### (c) 常见被 hook 的函数 
- 基础库，eg : libc  
基础库的函数多被上层接口调用，使用广泛； 符号表均为导出，且大多为基本数据类型，hook 极为方便；这里以linux平台为例，下面是 frida hook 脚本。
```
Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
        onEnter: function(args) {
            console.log("strstr, arg0="+Memory.readUtf8String(args[0]) + ", arg1:"+Memory.readUtf8String(args[1]));
        },
    });

    Interceptor.attach(Module.findExportByName("libc.so", "strlen"), {
        onEnter: function(args) {
            console.log("strlen, arg0="+Memory.readUtf8String(args[0]));
        },
    });

    Interceptor.attach(Module.findExportByName("libc.so", "strcpy"), {
        onEnter: function(args) {
            console.log("strcpy str src:" + Memory.readUtf8String (args [1]));
        },
        onLeave: function (retval) {
            console.log("strcpy, retval="+retval);
        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "strcmp"), {
        onEnter: function(args) {
            console.log("strcmp, arg0="+Memory.readUtf8String(args[0]) + ", arg1:"+Memory.readUtf8String(args[1]));
        },
    });
```
- 第三方sdk API  
  第三方sdk API多为公开，常被作为研究目标应用的入口点。例如，如果破解打卡应用，需要找到提供定位信息的API。应用可直接调用系统 LocationProvider，更常见的是调用第三方地图sdk。提供定位的接口，常被攻击者研究。
- 目标应用导出的函数  
  符号表导出，可直接在目标进程查询其函数地址，易于获取api输入，输出和返回值。
例如：上面的 Example 5 是通过 Module.getExportByName()  从目标进程搜索符号表对应的地址。 
- 目标应用核心逻辑函数  
  对于没有符号表导出的程序，也可通过动、静态分析，找到核心逻辑函数的地址，结合代码段基址计算出实际的函数地址。
  


## 4. 安全编码建议（防 hook）
根据上面的内容，可以大致了解攻击者 hook 的基本思路和范围：  
> a.  根据目标进程的特定场景，了解其调用接口；  （eg: 打卡应用， 定位信息相关接口）  
b. 如果接口函数均为导出，可直接打印其输入出入，查看内容，如果是字符串，可能携带有用信息；  
c. 研究基础库接口，打印输入出入内容，尤其涉及字符串的接口，以及比较函数，eg: strcmp, strncmp, strstr，可能会被用来引导程序控制流，会被攻击者关注；  
d. 攻击者找到目标函数，hook，查看输入输出。


了解 hook 的思路后，总结出下面几条安全编码建议，给攻击者 hook 添加障碍。
#### (a) 模块内部调用的接口，需要隐藏函数符号表
如果函数的符号表隐藏，攻击者需要动态计算函数的实际地址，可以将不少菜鸟黑客挡在门外。如果逻辑复杂，也能让有经验的黑客多忙活些时日。  
实施：

```
使用编译选项 -fvisibility=hidden，对于开放给其他模块使用的API，在函数前使用
__attribute__((visibility("default"))) 标记。
```


#### (b) 函数入参和返回值尽量传递对象，而不是基本类型或字符串
基本类型或字符串，容易构造，并被替换。这里以 Android https 证书绑定的破解为例。 证书绑定破解后，可以使用中间人攻击，获取明文的https数据包，查看 url 结构。 
Android app 绝大多会使用Java层的 https 实现，破解插件已经被写入逆向教程，较为简单，这里不提（参考 https://github.com/Fuzion24/JustTrustMe）。  
底层多基于 libopenssl 实现，暂未发现破解教程，不过也较易破解,下面列出 frida 脚本， hook ssl_verify_cert_chain函数，返回值改为1即可。


```
Interceptor.attach(Module.findExportByName("libopenssl.so", "ssl_verify_cert_chain"), {
  onEnter: function(args) {
    console.log('in ssl_verify_cert_chain');
  },
  onLeave: function(retval) {
    console.log('retval:'+retval)
    // 将返回值替换为1，表示校验通过
    retval.replace(1)
    console.log('retval after replace:'+retval)
  }
});
```
修改建议：  
- 返回值改为对象，对象里包含获取结果数据的函数。使得黑客不容易计算结果数据存放的内存地址。
- 多使用const对象和const成员变量，限定内存读写权限。
#### (c) 核心逻辑代码，避免使用基础库
基础库相关函数可以自己实现，实现方法可以直接搬运基础库源码。  
下面以破解常见的 Android 底层反调试为例。Android 底层常使用IDA，这类工具会 trace 目标进程，使得目标进程的status会存在"TracerPid" 字段，其字段值是调试工具的pid，所以常见的反调试，会检测这个字段值。
```
    /* 破解思路：hook strstr, 如果参数是 TracerPid， 则将返回值改为0，告诉调用者，没有找到这个字段 */
    Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
        onEnter: function(args) {
            // 获取入参字符串
            this.arg1 = ptr(args[1]).readUtf8String();
        },
        onLeave: function (retval) {
            // 比较入参是否有 "TracerPid"
            if(this.arg1.includes("TracerPid") ) {
                console.log("retval before is:"+retval);
                // 0 表示没有找到目标字符串
                retval.replace(0);
                console.log("retval after is:"+retval);
            }
        }
    });
```
修改建议：
- strstr 函数可以自己实现，不依赖基础库
- 字符串，可以加密后再放入代码，使用前调用解密函数。否则，明文字符串会存储在字符串段，容易被查看。

## 5. frida 脚本常用 API

API | 说明
---|---
Module.findExportByName(module， func_name)   | 从目标模块获取函数地址
frida.attach(proc_name) | attach目标进程
frida.get_usb_device().attach(proc_name) | 通过usb获取已连接的手机，attach到目标进程
Interceptor.attach(proc_name) | hook函数
Memory.alloc(size) | 目标进程的内存空间，分配内存
Memory.allocUtf8String(str) | 目标进程内存空间，分配内存并初始化字符串
hexdump(addr, options) | 从进程内存dump数据
Java.use(class_name)| 获取java class
Java.perform(fn) | 执行 fn

详细 API 参考：https://frida.re/docs/javascript-api/



## 6. 资料
frida 脚本库 https://github.com/iddoeldor/frida-snippets#file-access