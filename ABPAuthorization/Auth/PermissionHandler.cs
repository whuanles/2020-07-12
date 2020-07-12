using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace WebAuthorization
{

    /// <summary>
    /// 判断用户是否具有权限
    /// </summary>
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
}
