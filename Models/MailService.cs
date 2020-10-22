using System;
using System.Net.Mail;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;

namespace mailer.Models
{
    public class MailService
    {
        private readonly ICipherDriver cipherDriver;
        private readonly IConfiguration config;
        public MailService(IConfiguration config)
        {
            if (config["security:cipherDriver"] == "rc4") {
                this.cipherDriver = new Rc4(config["security:key"]);
            } else {
                this.cipherDriver = new SealDriver(config["security:key"]);
            }
            this.config = config;
        }

        // reads messages
        public List<MailModel> GetMessages()
        {
            List<MailModel> messages = new List<MailModel>();
            string title;
            string summary;

            System.Net.WebClient webclient = new System.Net.WebClient();

            // gmail log in
            webclient.Credentials = new System.Net.NetworkCredential(this.config["mailboxCredentials:logInAddress"], this.config["mailboxCredentials:logInPassword"]);
            // get contents
            string result = System.Text.Encoding.UTF8.GetString(webclient.DownloadData(@"https://mail.google.com/mail/feed/atom"));
            // messages.Add(new MailModel("abc", result)); return messages;
            // parse as xml
            System.Xml.XmlDocument doc = new System.Xml.XmlDocument();
            doc.LoadXml(result.Replace(@"<feed version=""0.3"" xmlns=""http://purl.org/atom/ns#"">", @"<feed>"));

            // generate list
            foreach (System.Xml.XmlNode node in doc.SelectNodes(@"/feed/entry")) {
                title = node.SelectSingleNode("title").InnerText;
                summary = node.SelectSingleNode("summary").InnerText;
                try {
                    string plain = this.cipherDriver.Decrypt(summary);
                    messages.Add(new MailModel(title, plain));
                } catch (Exception) {
                    // wiadomosc niekompatybilna z danym szyfrem np. szyfrowane rc4 a deszyfrowane seal
                    messages.Add(new MailModel(title, summary));
                }
            }

            return messages;
        }

        // sends a message to given address
        public void SendMessage(string to, string message, string subject)
        {
            string encrypted = "";

            encrypted = this.cipherDriver.Encrypt(message);

            MailMessage mail = new MailMessage();
            mail.From = new MailAddress(this.config["mailboxCredentials:logInAddress"]);
            mail.To.Add(to);
            mail.Subject = subject + " - (" + config["security:cipherDriver"] + ")";
            mail.Body = encrypted;

            SmtpClient client = new SmtpClient("smtp.gmail.com");
            client.Port = 587;
            client.Credentials = new System.Net.NetworkCredential(this.config["mailboxCredentials:logInAddress"], this.config["mailboxCredentials:logInPassword"]);
            client.EnableSsl = true;

            client.Send(mail);
        }
    }
}