using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace WebAuthorization
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
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


            services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();


            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
