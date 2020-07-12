using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Volo.Abp.Authorization.Permissions;

namespace WebAuthorization
{
    public class BookPermissionDefinitionProvider : PermissionDefinitionProvider
    {
        public override void Define(IPermissionDefinitionContext context)
        {
            var myGroup = context.AddGroup("Auth");
            var permission = myGroup.AddPermission("Book");
            permission.AddChild("Book:Add");
            permission.AddChild("Book:Remove");
            permission.AddChild("Book:Select");
            permission.AddChild("Book:Update");
        }
    }
}
