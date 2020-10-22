using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using mailer.Models;
// using MailKit;
// using MailKit.Net.Smtp;
// using MimeKit;
using Microsoft.Extensions.Configuration;

namespace mailer.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration config;

        public HomeController(IConfiguration config)
        {
            this.config = config;
        }

        public IActionResult Config()
        {
            return View();
        }

        public IActionResult Index()
        {
            if (testConfig()) {
                List<MailModel> messages = new List<MailModel>();
                MailService mailService = new MailService(this.config);
                try {
                    messages = mailService.GetMessages();
                } catch (Exception e) {
                    ViewBag.Status = e.ToString();
                }
                ViewBag.Messages = messages;
                return View();
            }
            return Redirect("/Home/Config");
        }


        // send new message
        public IActionResult New()
        {
            if (testConfig()) {
                return View();
            }
            return Redirect("/Home/Config");
        }

        // mails a message
        [HttpPost]
        public IActionResult Send(string message, string address, string subject = "Demo")
        {
            // message = "<zażółć gęślą jaźń> 0 1 2 3 4 5 6 7 8 9 (!@#$%^&*[];',./}{\":?~`)";
            // TODO validate
            if (message.Length > 20) {
                ViewBag.Status = "Maksymalna długość wiadomości to 20 znaków (ograniczenie gmail feed)" + "[" + message.Length + "]";
                return View("/Views/Home/New.cshtml");
            }
            MailService mailService = new MailService(this.config);
            try {
                mailService.SendMessage(address, message, subject);
            } catch (Exception e) {
                ViewBag.Status = "error: " + e.ToString();
                return Redirect("/Home/Error");
            }
            ViewBag.Status = "OK";
            return View("/Views/Home/New.cshtml");
        }

        // test mailbox config settings is ok
        private bool testConfig()
        {
            return ("" != this.config["mailboxCredentials:logInAddress"] && "" != this.config["mailboxCredentials:logInPassword"] 
            && "" != this.config["security:key"] && (this.config["security:cipherDriver"] == "seal" || this.config["security:cipherDriver"] == "rc4"));
        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
