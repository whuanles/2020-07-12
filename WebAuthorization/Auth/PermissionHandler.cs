using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using WebAuthorization.Auth;

namespace WebAuthorization
{

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
}
