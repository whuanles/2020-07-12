[TOC]

码云仓库源码地址 [https://github.com/whuanles/2020-07-12](https://github.com/whuanles/2020-07-12)

## ASP.NET Core 中的策略授权

首先我们来创建一个 WebAPI 应用。

然后引入 `Microsoft.AspNetCore.Authentication.JwtBearer` 包。



### 策略

Startup 类的 ConfigureServices 方法中，添加一个策略的形式如下：

```csharp
    services.AddAuthorization(options =>
    {
        options.AddPolicy("AtLeast21", policy =>
            policy.Requirements.Add(new MinimumAgeRequirement(21)));
    });
```

这里我们分步来说。

services.AddAuthorization 用于添加授权方式，目前只支持 AddPolicy。

ASP.NET Core 中，有基于角色、声明、策略的三种授权形式，都是使用 `AddPolicy` 来添加授权处理。

其中，有两个 API 如下：

```csharp
        public void AddPolicy(string name, AuthorizationPolicy policy);
        public void AddPolicy(string name, Action<AuthorizationPolicyBuilder> configurePolicy);
```

`name = "AtLeast21"`，这里 "AtLeast21" 是策略的名称。

`policy.Requirements.Add()` 用于添加一个策略的标记(存储此策略的数据)，此标记需要继承 `IAuthorizationRequirement` 接口。

策略的名称应该如何设置呢？在授权上应该如何编写策略以及使用 `Requirements.Add()`？

这里先放一放，我们接下来再讲解。



### 定义一个 Controller

我们来添加一个 Controller ：

```csharp
    [ApiController]
    [Route("[controller]")]
    public class BookController : ControllerBase
    {
        private static List<string> BookContent = new List<string>();
        [HttpGet("Add")]
        public string AddContent(string body)
        {
            BookContent.Add(body);
            return "success";
        }

        [HttpGet("Remove")]
        public string RemoveContent(int n)
        {
            BookContent.Remove(BookContent[n]);
            return "success";
        }

        [HttpGet("Select")]
        public List<object> SelectContent()
        {
            List<object> obj = new List<object>();
            int i = 0;
            foreach (var item in BookContent)
            {
                int tmp = i;
                i++;
                obj.Add(new { Num = tmp, Body = item });
            }
            return obj;
        }

        [HttpGet("Update")]
        public string UpdateContent(int n, string body)
        {
            BookContent[n] = body;
            return "success";
        }
    }
```

功能很简单，就是对列表内容增删查改。



### 设定权限

前面我们创建了 `BookController` ，具有增删查改的功能。应该为每一个功能都应该设置一种权限。

ASP.NET Core 中，一个权限标记，需要继承`IAuthorizationRequirement` 接口。

我们来设置五个权限：

添加一个文件，填写以下代码。

```csharp
    /*
     IAuthorizationRequirement 是一个空接口，具体对于授权的需求，其属性等信息是自定义的
     这里的继承关系也没有任何意义
     */

    // 能够访问 Book 的权限
    public class BookRequirment : IAuthorizationRequirement
    {
    }

    // 增删查改 Book 权限
    // 可以继承 IAuthorizationRequirement ，也可以继承 BookRequirment
    public class BookAddRequirment : BookRequirment
    {
    }
    public class BookRemoveRequirment : BookRequirment
    {
    }
    public class BookSelectRequirment : BookRequirment
    {
    }
    public class BookUpdateRequirment : BookRequirment
    {
    }
```



BookRequirment 代表能够访问 BookController，其它四个分别代表增删查改的权限。



### 定义策略

权限设定后，我们开始设置策略。

在 Startup 的 `ConfigureServices` 中，添加：

```csharp
            services.AddAuthorization(options =>
            {
                options.AddPolicy("Book", policy =>
                {
                    policy.Requirements.Add(new BookRequirment());
                });

                options.AddPolicy("Book:Add", policy =>
                {
                    policy.Requirements.Add(new BookAddRequirment());
                });

                options.AddPolicy("Book:Remove", policy =>
                {
                    policy.Requirements.Add(new BookRemoveRequirment());
                });

                options.AddPolicy("Book:Select", policy =>
                {
                    policy.Requirements.Add(new BookSelectRequirment());
                });

                options.AddPolicy("Book:Update", policy =>
                {
                    policy.Requirements.Add(new BookUpdateRequirment());
                });

            });
```

这里我们为每种策略只设置一种权限，当然每种策略都可以添加多个权限，

这里名称使用 `:` 隔开，主要是为了可读性，让人一看就知道是层次关系。



### 存储用户信息

这里为了更加简单，就不使用数据库了。

以下用户信息结构是随便写的。用户-角色-角色具有的权限。

这个权限用什么类型存储都可以。只要能够标识区分是哪个权限就行。

```csharp
    /// <summary>
    /// 存储用户信息
    /// </summary>
    public static class UsersData
    {
        public static readonly List<User> Users = new List<User>();
        static UsersData()
        {
            // 添加一个管理员
            Users.Add(new User
            {
                Name = "admin",
                Email = "admin@admin.com",
                Role = new Role
                {
                    Requirements = new List<Type>
                    {
                        typeof( BookRequirment),
                        typeof( BookAddRequirment),
                        typeof( BookRemoveRequirment),
                        typeof( BookSelectRequirment),
                        typeof( BookUpdateRequirment)
                    }
                }
            });

            // 没有删除权限
            Users.Add(new User
            {
                Name = "作者",
                Email = "wirter",
                Role = new Role
                {
                    Requirements = new List<Type>
                    {
                        typeof( BookRequirment),
                        typeof( BookAddRequirment),
                        typeof( BookRemoveRequirment),
                        typeof( BookSelectRequirment),
                    }
                }
            });
        }
    }

    public class User
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public Role Role { get; set; }
    }

    /// <summary>
    /// 这里的存储角色的策略授权，字符串数字等都行，只要能够存储表示就OK
    /// <para>在这里没有任何意义，只是标识的一种方式</param>
    /// </summary>
    public class Role
    {
        public List<Type> Requirements { get; set; }
    }
```



### 标记访问权限

定义策略完毕后，就要为 Controller 和 Action 标记访问权限了。

使用 `[Authorize(Policy = "{string}")]` 特性和属性来设置访问此 Controller 、 Action 所需要的权限。

这里我们分开设置，每个功能标记一种权限(最小粒度应该是一个功能 ，而不是一个 API)。

```csharp
    [Authorize(Policy = "Book")]
    [ApiController]
    [Route("[controller]")]
    public class BookController : ControllerBase
    {
        private static List<string> BookContent = new List<string>();

        [Authorize(Policy = "Book:Add")]
        [HttpGet("Add")]
        public string AddContent(string body){}

        [Authorize(Policy = "Book:Remove")]
        [HttpGet("Remove")]
        public string RemoveContent(int n){}

        [Authorize(Policy = "Book:Select")]
        [HttpGet("Select")]
        public List<object> SelectContent(){}

        [Authorize(Policy = "Book:Update")]
        [HttpGet("Update")]
        public string UpdateContent(int n, string body){}
    }
```



### 认证：Token 凭据

因为使用的是 WebAPI，所以使用 Bearer Token 认证，当然使用 Cookie 等也可以。使用什么认证方式都可以。

```csharp
            // 设置验证方式为 Bearer Token
            // 添加 using Microsoft.AspNetCore.Authentication.JwtBearer;
            // 你也可以使用 字符串 "Brearer" 代替 JwtBearerDefaults.AuthenticationScheme
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("abcdABCD1234abcdABCD1234")),    // 加密解密Token的密钥

                        // 是否验证发布者
                        ValidateIssuer = true,
                        // 发布者名称
                        ValidIssuer = "server",

                        // 是否验证订阅者
                        // 订阅者名称
                        ValidateAudience = true,
                        ValidAudience = "client007",

                        // 是否验证令牌有效期
                        ValidateLifetime = true,
                        // 每次颁发令牌，令牌有效时间
                        ClockSkew = TimeSpan.FromMinutes(120)
                    };
                });
```

上面的代码是一个模板，可以随便改。这里的认证方式跟我们的策略授权没什么关系。



### 颁发登录凭据

下面这个 Action 放置到 BookController，作为登录功能。这一部分也不重要，主要是为用户颁发凭据，以及标识用户。用户的 Claim 可以存储此用户的唯一标识。

```csharp
        /// <summary>
        /// 用户登录并且颁发凭据
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpGet("Token")]
        public string Token(string name)
        {
            User user = UsersData.Users.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (user is null)
                return "未找到此用户";

            // 定义用户信息
            var claims = new Claim[]
            {
                new Claim(ClaimTypes.Name, name),
                new Claim(JwtRegisteredClaimNames.Email, user.Email)
            };

            // 和 Startup 中的配置一致
            SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("abcdABCD1234abcdABCD1234"));

            JwtSecurityToken token = new JwtSecurityToken(
                issuer: "server",
                audience: "client007",
                claims: claims,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
            );

            string jwtToken = new JwtSecurityTokenHandler().WriteToken(token);
            return jwtToken;
        }
```

Configure 中补充以下两行：

```csharp
            app.UseAuthentication();
            app.UseAuthorization();

```





### 自定义授权

自定义授权需要继承 `IAuthorizationHandler` 接口，实现此接口的类能够决定是否对用户的访问进行授权。

实现代码如下：

```csharp
    /// <summary>
    /// 判断用户是否具有权限
    /// </summary>
    public class PermissionHandler : IAuthorizationHandler
    {
        public async Task HandleAsync(AuthorizationHandlerContext context)
        {
            // 当前访问 Controller/Action 所需要的权限(策略授权)
            IAuthorizationRequirement[] pendingRequirements = context.PendingRequirements.ToArray();

            // 取出用户信息
            IEnumerable<Claim> claims = context.User?.Claims;

            // 未登录或者取不到用户信息
            if (claims is null)
            {
                context.Fail();
                return;
            }


            // 取出用户名
            Claim userName = claims.FirstOrDefault(x => x.Type == ClaimTypes.Name);
            if (userName is null)
            {
                context.Fail();
                return;
            }
            // ... 省略一些检验过程 ...

            // 获取此用户的信息
            User user = UsersData.Users.FirstOrDefault(x => x.Name.Equals(userName.Value, StringComparison.OrdinalIgnoreCase));
            List<Type> auths = user.Role.Requirements;

            // 逐个检查
            foreach (IAuthorizationRequirement requirement in pendingRequirements)
            {
                // 如果用户权限列表中没有找到此权限的话
                if (!auths.Any(x => x == requirement.GetType()))
                    context.Fail();

                context.Succeed(requirement);
            }

            await Task.CompletedTask;
        }
    }
```

过程：

- 从上下文(Context) 中获取用户信息(context.User)
- 获取此用户所属的角色，并获取此角色具有的权限
- 获取此次请求的 Controller/Action 需要的权限(context.PendingRequirements)
- 检查所需要的权限(foreach循环)，此用户是否都具有



最后需要将此接口、服务，注册到容器中：

```csharp
services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
```



做完这些后，就可以测试授权了。



### IAuthorizationService

前面实现了 IAuthorizationHandler 接口的类，用于自定义确定用户是否有权访问此 Controller/Action。

IAuthorizationService 接口用于确定授权是否成功，其定义如下：

```csharp
public interface IAuthorizationService
    {
        Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, IEnumerable<IAuthorizationRequirement> requirements);

        Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, string policyName);
    }
```

`DefaultAuthorizationService ` 接口实现了 `IAuthorizationService` ，ASP.NET Core 默认使用 `DefaultAuthorizationService ` 来确认授权。



前面我们使用 `IAuthorizationHandler` 接口来自定义授权，如果再深入一层的话，就追溯到了`IAuthorizationService`。

`DefaultAuthorizationService `  是 `IAuthorizationService` 的默认实现，其中有一段代码如下：

![1594554987(H:/%E6%96%87%E7%AB%A0/ABP%20%E7%AD%96%E7%95%A5%E6%8E%88%E6%9D%83/images/1594554987(1).jpg)](./images/1594554987(1).jpg)

`DefaultAuthorizationService `  比较复杂，一般情况下，我们只要实现 `IAuthorizationHandler` ` 就够了。

参考资料：[https://docs.microsoft.com/zh-cn/dotnet/api/microsoft.aspnetcore.authorization.defaultauthorizationservice?view=aspnetcore-3.1](https://docs.microsoft.com/zh-cn/dotnet/api/microsoft.aspnetcore.authorization.defaultauthorizationservice?view=aspnetcore-3.1)



## ABP 授权

前面已经介绍了 ASP.NET Core 中的策略授权，这里介绍一下 ABP 中的授权，我们继续利用前面已经实现的 ASP.NET Core 代码。

### 创建 ABP 应用

Nuget 安装 `Volo.Abp.AspNetCore.Mvc`、`Volo.Abp.Autofac` 。

创建 `AppModule` 类，代码如下：

```csharp
    [DependsOn(typeof(AbpAspNetCoreMvcModule))]
    [DependsOn(typeof(AbpAutofacModule))]
    public class AppModule : AbpModule
    {
        public override void OnApplicationInitialization(
            ApplicationInitializationContext context)
        {
            var app = context.GetApplicationBuilder();
            var env = context.GetEnvironment();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            app.UseStaticFiles();
            app.UseRouting();
            app.UseConfiguredEndpoints();
        }
    }
```

在 Program 的 Host 加上 `.UseServiceProviderFactory(new AutofacServiceProviderFactory())`，示例如下：

```csharp
        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
            .UseServiceProviderFactory(new AutofacServiceProviderFactory())
            ...
            ...

```

然后在 Startup 中的 `ConfiguraServices` 方法中，添加 ABP 模块， 并且设置使用 Autofac。

```csharp
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddApplication<AppModule>(options=>
            {
                options.UseAutofac();
            });
        }

```



### 定义权限

ABP 中使用 `PermissionDefinitionProvider` 类来定义权限，创建一个类，其代码如下：

```csharp
    public class BookPermissionDefinitionProvider : PermissionDefinitionProvider
    {
        public override void Define(IPermissionDefinitionContext context)
        {
            var myGroup = context.AddGroup("Book");
            var permission = myGroup.AddPermission("Book");
            permission.AddChild("Book:Add");
            permission.AddChild("Book:Remove");
            permission.AddChild("Book:Select");
            permission.AddChild("Book:Update");
        }
    }

```

这里定义了一个组 `Book`，定义了一个权限 `Book`了，`Book` 其下有四个子权限。

删除 Startup 中的`services.AddAuthorization(options =>...` 。

将剩余的依赖注入服务代码移动到 AppModule 的 `ConfigureServices` 中。

Startup 的 Configure 改成：

```csharp
            app.InitializeApplication();

```

AbpModule 中的 `Configure` 改成：

```csharp
            var app = context.GetApplicationBuilder();
            var env = context.GetEnvironment();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            app.UseStaticFiles();
            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseConfiguredEndpoints();

```

PermissionHandler 需要改成：

```csharp
    public class PermissionHandler : IAuthorizationHandler
    {
        public Task HandleAsync(AuthorizationHandlerContext context)
        {
            // 当前访问 Controller/Action 所需要的权限(策略授权)
            IAuthorizationRequirement[] pendingRequirements = context.PendingRequirements.ToArray();

            // 逐个检查
            foreach (IAuthorizationRequirement requirement in pendingRequirements)
            {
                context.Succeed(requirement);
            }


            return Task.CompletedTask;
        }
    }

```

删除 UserData 文件；BookController 需要修改一下登录和凭证。

具体细节可参考仓库源码。