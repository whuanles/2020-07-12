﻿using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Razor.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using WebAuthorization.Auth;

namespace WebAuthorization.Controllers
{
    [Authorize(Policy = "Book")]
    [ApiController]
    [Route("[controller]")]
    public class BookController : ControllerBase
    {
        private static List<string> BookContent = new List<string>();


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

        [Authorize(Policy = "Book:Add")]
        [HttpGet("Add")]
        public string AddContent(string body)
        {
            BookContent.Add(body);
            return "success";
        }

        [Authorize(Policy = "Book:Remove")]
        [HttpGet("Remove")]
        public string RemoveContent(int n)
        {
            BookContent.Remove(BookContent[n]);
            return "success";
        }

        [Authorize(Policy = "Book:Select")]
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

        [Authorize(Policy = "Book:Update")]
        [HttpGet("Update")]
        public string UpdateContent(int n, string body)
        {
            BookContent[n] = body;
            return "success";
        }
    }
}
