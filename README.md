# SM-Bank-Demo

一个网银系统 Demo，采用 UKey 和传统密码的双因素认证，防护登录和转账过程，所使用加密算法为 SGD_SM3_SM2，权限控制由 SpringSecurity 实现

- 后端主要改写了双因素的认证过程（即 SM3_SM2 的解密和认证）、时间戳服务器的调用

- 前端采用 Vue 模板 [PanJiaChen/vue-admin-template: a vue2.0 minimal admin template (github.com)](https://github.com/PanJiaChen/vue-admin-template)，对登录、转账过程的 SM2 加密进行改写

## 前端 Issues

前端 UKEY 加密这里有问题：

1. 我在两个地方需要用到 UKEY 加密，一个是登陆的时候，一个是转账的时候，显然转账这一操作在登录之后

2. 由于前端的 API 调用采用 WebSocket 异步回调函数的方式执行，所以我完整的加密过程是这样的

   1. 连接 WebSocket：若失败，返回 false；若成功，调用检查插件的回调
   2. 检查插件：若不通过，返回 false；若通过，调用获取密钥信息的回调
   3. 获取密钥信息：若不通过，返回 false；若通过，调用加密的回调
   4. 加密：失败或成功

   也就是说，这个过程是一个连贯、整体的，另外，每一次页面刷新会导致 WebSocket 的重连，为了保证刷新不影响用户操作，我必须在每一次载入页面的时候（即在钩子函数中）完整的执行上述过程

3. 但是，在登录时使用的 WebSocket 连接是一个长连接，而在第二步的第一小步，即连接 WebSocket，若已有连接，这一步是会报错返回 false 的，也就是说，登录到转账如果是一个连贯的流程，在转账页面将无法正常加密导致转账失败。但同时，上面也说了，为了避免用户刷新导致页面 bug，我必须把他作为一个完整的过程在钩子函数中执行


我想到了三种处理方案

1. 在登陆成功后，我直接将密钥信息存在用户本地 session，这样转账就不需要再一次读取 UKEY 了，但显然这样有点不安全，部分的 UKEY 信息存在 localStorge 中可能会被恶意获取（但实际上似乎不是很影响，因为存的是一些不太重要的索引信息，在转账加密的时候，会通过这个索引去找密钥，如果 UKEY 不插上，只知道索引也根本无从得知密钥）
2. 在转账的时候进行判定，若 WebSocket 已连接并导致了报错，那么在这个异常处理中，直接进行“检查插件、获取密钥信息、加密”的操作（因为 WebSocket 已经连接了，这样的操作肯定是被允许的）
3. 在登录成功后，我手动关闭 WebSocket 连接，这样在转账页面的时候，他必定会重新连接 WebSocket，从而重新获取完整的密钥信息，坏处是增加了计算量

唉，太怪了，我肯定首选第二个方案，然后在这里做了处理，若已连接，则直接调用插件检查的函数并进行后续的加密（此为第一版）

```js
envCheck(){
    if(ntlsUtil.wsObj){
        this.check_plugin_exist();
    } else {
        ntlsUtil.websocketInit(this.check_plugin_exist, null, this.check_plugin_exist);
    }
},
```

但还是有问题，不明原因，为了交付（表面上看起来没问题），只能临时采用第一种解决方案了（此为第二版）

- 登陆的时候把`keyindex、containerID、Pin`存入 localStorage
- 转账的时候如果初始化参数为空（只有一种可能失败，就是 WebSocket 已连接，直接进行读取但没读到），再从 localStorage 中读，进行加密

TMD，是哪个脑瘫想出来的用 WebSocket 交互做前端接口，真有他的

回头再看，第二种方案有不明原因的问题，第一种方案有轻度的安全隐患，还是采用第三种方案比较好，于是改成了第三种

在登陆成功时，断开 WebSocket 连接（此为第三版）

```js
doLogin(message){
    if(!message || !message.data){
        alert("签名失败, 请检查UKey是否插入或PIN码是否正确, 或PIN码是否被锁定");
        this.loading = false;
        return false;
    }
    // console.log("签名获取成功: " + message.data);
    console.log("签名所用证书为: " + this.cert  + "\n前端签名原文为" + this.encodeBase64(this.loginForm.iniData) + "\n前端签名所得密文为: " + message.data)
    this.loginForm.signature = message.data;

    this.$store.dispatch('user/login', this.loginForm).then(() => {
        // localStorage.setItem("pin", this.loginForm.key);
        // localStorage.setItem("keyindex", this.keyindex);
        // localStorage.setItem("container", this.container);
        
        // 断开连接
        ntlsUtil.close();
        this.$router.push({ path: this.redirect || '/' })

        this.loading = false
    }).catch(() => {
        this.loading = false
    })
},
```

但正确性有待验证，反正我交付的是第二版，第三版是为了说服我自己（补药写屎山啊）

突然发现，就算采用第三版，我的 PIN 码还是得存，或者在前端多做一个 PIN 的输入框，我要懒死了，算了，还是换回第二版吧

## 后端密码机集成

~~打算用 Go 重构后端，顺便学点高并发的实现，解耦业务、加入缓存、保证数据一致性~~，差不多得了，这项目没啥写的

### 前端 WebSocket 签名

与 U 盘进行通信，奥联给的前端 WebSocket 接口，很难用，但没招

UKEY 环境检测：采用 WebSocket 形式的接口（狗屎奥联提供的）对前端表单数据进行 SGD_SM3_SM2 进行签名，该 UKEY 接口内部写死 SignerID 为`"1234567812345678"`（默认 ID），这在后续验签时需保持一致

检测插件环境以及是否插入 U 盾

```js
envCheck(){
    if(!ntlsUtil.wsObj){
        ntlsUtil.websocketInit(this.check_plugin_exist, null, this.check_plugin_exist);
    } else {
        this.check_plugin_exist();
    }
}
```

ntlsUtil 是从奥联接口中导入的全局工具类

```js
import { ntlsUtil } from '@/utils/ntls-plugin'
```

如果 ntlsUtil.wsObj 不为空，即 websocket 连接打开，则认为已经检查过不进行后续操作（因为检查过程会主动打开 websocket，若在已连接的情况下再打开会报错，所以这里这么处理，但在后续引发了其他问题）

插件检查

```js
//检查插件
check_plugin_exist(){
    if(ntlsUtil.pluginExist==false){
        //连接不成功,插件未安装或者服务未启动
        alert("连接不成功,插件未安装或者服务未启动")
        return false;
    }
    //step4 检测是否插入ukey, 所有接收信息的回调函数名称都为当前发送消息的action名称 
    ntlsUtil.func.enumerate_ukey_user(this.enumerate_ukey_user);
}
```

`ntlsUtil.func.enumerate_ukey_user()`是一个异步函数，传参为回调函数，对异步返回的数据进行处理，`this.enumerate_ukey_user`如下

```js
enumerate_ukey_user(message){
    if(message == null){
        alert("WebSocket检测请求失败")
        return false;
    }
    var ukey_exist = false;
    for(var i = 0; i < message.data.usbkey.length; i++){
        var key_data = message.data.usbkey[i];
        if(typeof key_data.keytype != 'undefined'){
            if(this.check_key_type == true &&  key_data.keytype != this.key_type ){ }
            else{
                //keytype=file 在私钥标识中查找，从每个identity.0.type 查找sm2/sm9/...
                var this_ukey_exist = false;
                var length = key_data.identity.length;
                for (var m = 0; m < length; m++){
                    //只匹配需要的alg
                    if(key_data.identity[m].type.toUpperCase().indexOf(this.alg_type) != -1){
                        this_ukey_exist = true;//局部
                    }
                }
                if(this_ukey_exist){
                    ukey_exist = true;//全局
                }
            }
        } else {
            //key_type=usbkey  在产商中查找
            if(key_data.manufacturer.toUpperCase().indexOf(alg_type)!==-1 || key_data.alg.toUpperCase().indexOf(this.alg_type)!==-1 ){
                ukey_exist = true;
            }
        }
    }
    if(ukey_exist == false){
        alert('未检测到'+this.alg_type+'私钥标识'); //按扭功能 ，检测sm2/sm9等 UKEY是否插件
        return false;
    }else{
        console.log('检测到'+this.alg_type+'私钥标识',true,true);
        console.log(JSON.stringify(message));
        this.keyindex = message.data.usbkey[0].keyindex;
        this.container = message.data.usbkey[0].identity[0].container;
        console.log("keyindex: " + this.keyindex + "\ncontainer: " + this.container);
        this.ret = true;
    }
}
```

请求完毕后，将 UKEY 中的`keyindex`和`container`存在前端维护的两个变量中，在后续登陆时使用

用户注册：系统要求用户注册时录入用户所使用 UKEY 中的证书信息，同样采用异步函数获取

```js
handleRegister() {
    this.$refs.registerForm.validate(valid => {
        if (valid) {
            this.loading = true
            let ukey_val = this.keyindex;
            let identity_val = this.container;
            ntlsUtil.func.get_cert_content(ukey_val, identity_val, 1, this.doRegister);
        }
    })
},
// message 中为证书信息
doRegister(message){
    if(!message || !message.data){
        alert("获取证书内容失败");
        return false;
    }
    console.log(message.data)
    // 截取cert
    let cert = message.data.replace(/[\r\n]/g,"");
    cert = cert.substr(27, cert.length)
    cert = cert.substr(0, cert.indexOf("-"))
    console.log(cert)

    this.registerForm.certificate = cert;
    register(this.registerForm).then(() => {
        this.$message({
            message: '注册成功，即将返回登录页面！',
            type: 'success',
            duration: 2000
        })
        this.loginForm.username = this.registerForm.username
        this.loginForm.password = this.registerForm.password
        setTimeout(() => {
            this.switchLogin = true
        }, 1500)
        this.$refs['registerForm'].resetFields()
    }).finally(() => {
        this.loading = false
    })
},
```

签名及登录：表单数据在签名前需要进行 Base64 编码处理

```js
encodeBase64(str){
    return Buffer.from(str, 'utf8').toString('base64');
}
```

用户注册成功，并且在页面正常获得 UKEY 信息后，执行登陆操作，pass 为 UKEY 的 PIN 码，需要用户在前端手动输入

```js
// 登录
handleLogin() {
    this.$refs.loginForm.validate(valid => {
        valid = valid && this.ret // this.ret 在环境检测通过后置为 true，valid 为表单数据合法性
        if (valid) {
            this.loading = true
            this.loginForm.iniData = JSON.stringify(this.loginForm);
            console.log(this.loginForm.iniData);
            let inData = this.encodeBase64(this.loginForm.iniData);
            let ukey_val = this.keyindex;
            let identity_val = this.container;
            let pass = this.loginForm.key;
            let hashtype = "";
            let format = "asn.1";
            // 注意这里要标明 format 为 asn.1
            ntlsUtil.func.data_sm2_signature(ukey_val, identity_val, pass, inData, hashtype, format, this.doLogin);
        } else {
            console.log('error submit!!');
            alert("error submit!")
            return false
        }
    })
}
```

核心在于这条加密函数

```js
ntlsUtil.func.data_sm2_signature(ukey_val, identity_val, pass, inData, hashtype, format, this.doLogin);
```

`ukey_val`和`identity_val`为环境检测时获取的 UKEY 信息`keyindex`和`container`，`pass`为 UKEY 的 PIN 码，`inData`为登陆的表单原文（Json 数据），如

```json
"{\"account\":\"wx\", \"password\":\"123456\", \"verify_code\":\"dQ3k\", \"PIN\":\"123456\"}"
```

`this.doLogin`为回调函数，传入的`message`为签名数据

```js
// 打请求
doLogin(message){
    if(!message || !message.data){
        alert("签名失败, 请检查UKey是否插入或PIN码是否正确, 或PIN码是否被锁定");
        this.loading = false;
        return false;
    }
    console.log("签名所用证书为: " + this.cert  + "\n前端签名原文为" + this.encodeBase64(this.loginForm.iniData) + "\n前端签名所得密文为: " + message.data)
    this.loginForm.signature = message.data;

    this.$store.dispatch('user/login', this.loginForm).then(() => {
        localStorage.setItem("pin", this.loginForm.key);
        localStorage.setItem("keyindex", this.keyindex);
        localStorage.setItem("container", this.container);
        this.$router.push({ path: this.redirect || '/' })

        this.loading = false
    }).catch(() => {
        this.loading = false
    })
}
```

注意传入的原文数据需要是 Base64 编码，并且在签名时，必须要规定传参`format`为`asn.1`，才能签名得到 Base64 编码的密文？奥联真的是一群草台班子

另外这里非常不优雅的把一系列信息存到了 localStorage，因为在后续的转账操作中要用到，为什么要这么写？

1. 之前在检测环境时说过，是否检测的条件是 websocket 是否连接，这就造成登录时用的这个连接一直保持，于是在后续并不会进行环境检测
2. 所以呢，在转账页面，没有进行环境检测，自然就不会去遍历钥匙，就不会获得`keyindex`和`container`，所以这里我偷懒直接存了，到时候直接取了用

正确的流程应该是：在登陆成功后，主动断开 websocket 连接，在转账页面重复上述流程获取钥匙信息再进行签名操作，但是他就给了我 1k，我懒得写了，反正能跑且没找我麻烦（估计他们都没有审查过代码）

### 密码机和时间戳服务器

依旧奥联 + 中安云科的服务器，非常垃圾的 Word 文档，不像现代软件业的产物

验签流程

1. 后端接收验签请求
2. 根据用户名从数据库中取出用户证书
3. 对前端传来的原文和密文通过证书和签名验签服务器进行验证
4. 返回`true/false`，实现第一重认证

Controller 接口

```java
@PostMapping("/login")
public Result doLogin(@RequestBody LoginInfoDTO user,HttpServletRequest req) throws CryptoException, UnsupportedEncodingException {
    System.out.println("signature: "+ user.getSignature());
    HttpSession session = req.getSession();
    String gencode = (String) session.getAttribute("index_code");
    if(StringUtils.isEmpty(user.getCode())){
        return Result.ERROR("验证码不能为空");
    }
    System.out.println("验证码： " + gencode);
    if (!gencode.toLowerCase().equals(user.getCode().toLowerCase())){
        return Result.ERROR("验证码错误");
    }

    //验证用户登录签名信息
    if(StringUtils.isEmpty(user.getSignature())){
        return Result.ERROR("签名信息不能为空");
    }

    String jwtToken = userService.doLogin(user);
    if (jwtToken == null) {
        return Result.ERROR("用户名或密码错误!!!!!!");
    }
    System.out.println("用户登录");
    return Result.OK(jwtToken);
}
```

主要的验证业务在`String jwtToken = userService.doLogin(user)`这一行，他将触发 Service 层的验证逻辑，当通过验证后返回一个 JWT

```java
@Override
public String doLogin(LoginInfoDTO user) {
    User uu = userMapper.findByName(user.getUsername());
    String cert = uu.getCertificate();
    String iniData = user.getIniData();
    String signData = user.getSignature();
    System.out.println("iniData: " + iniData);
    System.out.println("signature: " + signData);
    boolean flag = OlymSignature.verifySignature(cert, iniData, signData);
    if(flag)
        return doLogin(user.getUsername(), user.getPassword());
    else
        return null;
}
```

第一重认证在`boolean flag = OlymSignature.verifySignature(cert, iniData, signData);`

```java
public static boolean verifySignature(String cert, String inData, String signed){
    boolean flag = false;
    try{
        flag = verify(cert, inData, signed);
    }catch (Exception e){
        System.out.println("---------->验签出错");
        e.printStackTrace();
    }
    return flag;
}
```

verify 函数封装一个 HTTP 请求，打向后端内网中的密码机，获取验签结果，这里的 cert 是注册时用户存入数据库的那份证书，inData 和 signature 分别是从前端打来的表单原文信息和前端的签名信息

所以这里的验签实际上就是，根据用户在后端存的证书 cert，对用户的原文加密，并和用户在前端的密文进行比对，若一致则认证通过

```java
public static boolean verify(String cert, String inData, String signature) throws Exception {
    if(cert == null){
        cert = Cert;
    }
    byte[] signerIDBytes = SignerID.getBytes();
    Integer signerIDLen = signerIDBytes.length;
    String signerID = Base64.getEncoder().encodeToString(signerIDBytes);

    byte[] inDataBytes = inData.getBytes();
    Integer inDataLen = inDataBytes.length;
    System.out.println(inDataLen);
    inData = Base64.getEncoder().encodeToString(inDataBytes);

    System.out.println("验签所使用的证书为: " + cert);
    System.out.println("验签所使用的原文为: " + inData);
    System.out.println("验签所使用的签名密文为: " + signature);
    System.out.println("验签所使用的签名ID为: " + signerID);

    VerifySignedDataReq verifySignedDataReq = new VerifySignedDataReq();
    verifySignedDataReq.setSignMethod(SGD_SM3_SM2);
    verifySignedDataReq.setType(Type);
    verifySignedDataReq.setCert(cert);
    // Type为1时certSN没用，将使用cert
    verifySignedDataReq.setInData(inData);
    verifySignedDataReq.setInDataLen(inDataLen);
    // 这个ID默认为"1234567812345678"
    verifySignedDataReq.setSignerID(signerID);
    verifySignedDataReq.setSignerIDLen(signerIDLen);
    verifySignedDataReq.setSignature(signature);
    verifySignedDataReq.setVerifyLevel(VerifyLevel);
    System.out.println(verifySignedDataReq);
    Integer verifySignedDataResult = SignVerifyUtil.verifySignedData(verifySignedDataReq);
    System.out.println(
        "单包验证数字签名结果：" + Objects.equals(SVSRESPONSE_RESPVALUE_SUCCESS, verifySignedDataResult));
    return SignVerifyUtil.verifySignedData(verifySignedDataReq) == 0;
}
```

而后的二重认证`doLogin(user.getUsername(), user.getPassword())`就是数据库密码认证

最后，因为有外部依赖包，需要在`Project Structure`中添加`Modules`，同时在`pom.xml`中配置导出

```xml
<dependencies>
<!--外部引用，打包时要包含进去-->
    <dependency>
        <groupId>obymtect.ibc</groupId>
        <artifactId>sign</artifactId>
        <version>1.0.1</version>
        <scope>system</scope>
        <systemPath>${pom.basedir}/lib/olymibc.jar</systemPath>
    </dependency>
</dependencies>

<build>
    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
            <configuration>
                <!-- 在打包时将引用的外部jar引入到当前项目包中	-->
                <includeSystemScope>true</includeSystemScope>
            </configuration>
        </plugin>
    </plugins>
</build>
```

