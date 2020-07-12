using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebAuthorization.Auth
{
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
                        typeof(BookRequirment),
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
}
