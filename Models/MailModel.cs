namespace mailer.Models
{
    public class MailModel
    {
        private string title;
        private string content;
        public MailModel(string title, string content) {
            this.title = title;
            this.content = content;
        }

        public string getTitle()
        {
            return this.title;
        }
        public string getContent()
        {
            return this.content;
        }

        public void setTitle(string title)
        {
            this.title = title;
        }
        public void setContent(string content)
        {
            this.content = content;
        }
    }
}