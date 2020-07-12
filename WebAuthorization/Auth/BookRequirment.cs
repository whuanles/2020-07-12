using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebAuthorization
{
    /*
     IAuthorizationRequirement 是一个空接口，具体对于授权的需求，其属性等信息是自定义的
     这里的继承关系也没有任何意义
     */

    // 能够访问 Book 的权限
    public class BookRequirment : IAuthorizationRequirement
    {
    }

    // 增删查改 Book 权限
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
}
