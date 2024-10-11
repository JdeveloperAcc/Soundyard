using System;
using System.ComponentModel;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Club.Soundyard.Web.Models;

//todo swith over into required namespace
namespace Club.Soundyard.Web
{
    public class EmailService : IIdentityMessageService
    {
        internal static readonly string Domain = ConfigurationManager.AppSettings["Web_Domain"];

        internal static readonly string AdminName = ConfigurationManager.AppSettings["Web_AdminName"];

        internal static readonly string ClearanceName = ConfigurationManager.AppSettings["Web_ClearanceName"];

        public async Task SendAsync(IdentityMessage message)
        {
            await configSendGridAsync(message);
        }


        // SendGrid by Twilio integration ...
        /*
        private async Task configSendGridAsync(IdentityMessage message)
        {
            // Send message via SMTP Server...
            string clearanceEmail = string.Concat(ClearanceName, '@', Domain);

            var myMessage = new SendGrid.Helpers.Mail.SendGridMessage();
            myMessage.AddTo(message.Destination);
            myMessage.From = new SendGrid.Helpers.Mail.EmailAddress(
                                clearanceEmail, ClearanceName);
            myMessage.Subject = message.Subject;
            myMessage.PlainTextContent = message.Body;
            myMessage.HtmlContent = message.Body;

            var credentials = new System.Net.NetworkCredential(
                       ConfigurationManager.AppSettings["mailAccount"],
                       ConfigurationManager.AppSettings["mailPassword"]
                       );

            // Create a Web transport for sending email.
            var transportWeb = new SendGrid.Web(credentials);

            // Send the email.
            if (transportWeb != null)
            {
                try
                {
                    await transportWeb.DeliverAsync(myMessage);
                }
                catch (Exception ex)
                {
                    Trace.TraceError(ex.ToString());
                }
            }
            else
            {
                Trace.TraceError("Failed to create Web transport.");
                await Task.FromResult(0);
            }
        }
        */

        // .Net System.Net.Mail SmtClient integration ...
        private async Task configSendGridAsync(IdentityMessage message)
        {
            // Send message via SMTP Server...
            string clearanceEmail = string.Concat(ClearanceName, '@', Domain);
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12 | SecurityProtocolType.Ssl3;

            SmtpClient client = new SmtpClient();
            // Read config from <configuration><system.net><mailSettings><smtp><network>...

            MailAddress from = new MailAddress(clearanceEmail, ClearanceName, System.Text.Encoding.UTF8);
            MailAddress to = new MailAddress(message.Destination);

            MailMessage emailMsg = new MailMessage(from, to);
            emailMsg.Body = message.Body;
            emailMsg.BodyEncoding = System.Text.Encoding.UTF8;
            emailMsg.IsBodyHtml = true;
            emailMsg.Subject = message.Subject;
            emailMsg.SubjectEncoding = System.Text.Encoding.UTF8;

            // Set the method that is called back when the send operation ends.
            client.SendCompleted += new SendCompletedEventHandler(SendCompletedCallback);
            string token = $"a confirmation email at {DateTime.Now}";

            try
            {
                Thread thread2nd = new Thread(() => client.SendAsync(emailMsg, token));
                thread2nd.Start();
            }
            catch (Exception ex)
            {
                Trace.TraceError(ex.ToString());
            }
            finally
            {
                emailMsg.Dispose();
                await Task.FromResult(0);
            }
        }

        private static void SendCompletedCallback(object sender, AsyncCompletedEventArgs e)
        {
            // Get the unique identifier for this asynchronous operation.
            String token = (string)e.UserState;

            if (e.Cancelled)
            {
                Trace.WriteLine($"[{token}] Send canceled.");
            }
            if (e.Error != null)
            {
                Trace.WriteLine($"[{token}] {e.Error} / {e.Error?.InnerException}");
            }
            else
            {
                Trace.WriteLine($"[{token}] Message sent.");
            }
        }

    }

    // Configure the application user manager used in this application. UserManager is defined in ASP.NET Identity and is used by the application.
    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        public ApplicationUserManager(IUserStore<ApplicationUser> store)
            : base(store)
        {
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context)
        {
            var manager = new ApplicationUserManager(new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()));
            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<ApplicationUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };

            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            // Configure user lockout defaults
            manager.UserLockoutEnabledByDefault = true;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;

            // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            // You can write your own provider and plug it in here.
            manager.RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<ApplicationUser>
            {
                MessageFormat = "Your security code is {0}"
            });
            manager.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<ApplicationUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your security code is {0}"
            });
            manager.EmailService = new EmailService();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider =
                    new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }
    }

    // Configure the application sign-in manager which is used in this application.
    public class ApplicationSignInManager : SignInManager<ApplicationUser, string>
    {
        public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }

        public override Task<ClaimsIdentity> CreateUserIdentityAsync(ApplicationUser user)
        {
            return user.GenerateUserIdentityAsync((ApplicationUserManager)UserManager);
        }

        public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
        {
            return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
        }
    }

    // Configure the application role manager which is used in this application.
    public class ApplicationRoleManager : RoleManager<IdentityRole>
    {
        public static readonly string[] RoleNames = new string[] { "Administrator", "Editor", "Customer" };

        public ApplicationRoleManager(IRoleStore<IdentityRole, string> store)
            : base(store)
        {
        }

        public static ApplicationRoleManager Create(IdentityFactoryOptions<ApplicationRoleManager> options,
            IOwinContext context)
        {
            var dbContext = context.Get<ApplicationDbContext>();

            var manager = new ApplicationRoleManager(new
                RoleStore<IdentityRole>(dbContext));

            if (dbContext != null && !dbContext.Roles.Any())
            {
                foreach (string role in RoleNames)
                {
                    if (!manager.RoleExists(role))
                    {
                        manager.Create(new IdentityRole(role));
                    }
                }
            }

            return manager;
        }

        public static string AssignRoleToEmail(string emailAddress)
        {
            string email = emailAddress.ToLower();

            if (emailAddress == string.Concat(EmailService.AdminName, '@', EmailService.Domain))
                return RoleNames[0];
            else if (emailAddress.Contains(string.Concat('@', EmailService.Domain)))
                return RoleNames[1];
            else
                return RoleNames[2];
        }
    }
}
