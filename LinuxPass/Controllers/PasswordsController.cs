using LinuxPass.Data;
using LinuxPass.Models;
using LinuxPass.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Web;

namespace LinuxPass.Controllers
{
    public class PasswordsController : Controller
    {
        private readonly LinuxPassMngContext _context;
        private readonly IConfiguration _configuration;

        // Combine both constructors into one
        public PasswordsController(LinuxPassMngContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        // GET: Passwords
        public async Task<IActionResult> Index(string searchString, string searchString2)
        {
            if (_context.Passwords == null)
            {
                return Problem("Entity set PasswordsContext is null.");
            }

            var passwords = from m in _context.Passwords
                            select m;

            if (!String.IsNullOrEmpty(searchString))
            {
                passwords = passwords.Where(s => s.Username!.ToUpper().Contains(searchString.ToUpper()));
            }
            if (!String.IsNullOrEmpty(searchString2))
            {
                passwords = passwords.Where(s => s.Servername!.ToUpper().Contains(searchString2.ToUpper()));
            }

            var uniquePasswords = await passwords
            .GroupBy(s => new { s.Username, s.Servername })
            .Select(g => g.OrderByDescending(s => s.AddTime).FirstOrDefault())
            .ToListAsync();

            return View(uniquePasswords);
        }
        // GET: Passwords/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var password = await _context.Passwords
                .FirstOrDefaultAsync(m => m.Id == id);
            if (password == null)
            {
                return NotFound();
            }
            try
            {
                string encryptionKey = _configuration["EncryptionKey"] ?? "";
                string servername = password.Servername;
                string encryptedPassword = password.EncryptedPassword;
                string decryptedpass = CryptorService.Cryptor.DecryptString(encryptedPassword, encryptionKey);
                var passwordDetails = new PasswordDetailsViewModel
                {
                    Id = password.Id,
                    Username = password.Username,
                    Servername = password.Servername,
                    DecryptedPassword = decryptedpass
                };
                return View(passwordDetails);
            }
            catch (Exception ex)
            {
                return Problem($"error: {ex}");
            }

        }

        // GET: Passwords/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Passwords/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,Username,Servername,EncryptedPassword,AddTime")] Password password)
        {
            string generatedpass = PassGenService.GeneratePassword(12, PassGenService.Complexity.Low);
            if (string.IsNullOrEmpty(generatedpass))
            {
                ViewData["Message"] = "Failed to generate password.";
                return View(password);
            }
            string sshKeypath = _configuration["SSHKeyPath"] ?? "";
            var sshUser = await _context.Servers.FirstOrDefaultAsync(s => s.HostSrvName == password.Servername);
            if (sshUser == null)
            {
                ViewData["Message"] = "Server not found.";
                return View(password);
            }
            // Check if user already exists with the same server name
            var existingUser = await _context.Passwords.FirstOrDefaultAsync(p => p.Username == password.Username && p.Servername == password.Servername);
            if (existingUser != null)
            {
                ViewData["Message"] = "User already exists for this server name.";
                return View(password);
            }
            AddUserService addUserService = new AddUserService(_context, _configuration);
            string result = addUserService.AddUser(password.Servername, sshUser.HostSrvUsername, sshKeypath, password.Username, generatedpass);
            if (result == "Success")
            {
                password.EncryptedPassword = CryptorService.Cryptor.EncryptString(generatedpass, _configuration["EncryptionKey"] ?? "");
                password.AddTime = DateTime.Now;
                _context.Add(password);
                await _context.SaveChangesAsync();
                ViewData["Message"] = "User created successfully.";
                return View(password);
            }
            else
            {
                ViewData["Message"] = result;
                return View(password);
            }
        }


        // GET: Passwords/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var password = await _context.Passwords
                .FirstOrDefaultAsync(m => m.Id == id);
            if (password == null)
            {
                return NotFound();
            }

            return View(password);
        }

        // POST: Passwords/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var password = await _context.Passwords.FindAsync(id);
            if (password != null)
            {
                _context.Passwords.Remove(password);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        // POST: SMS/SendSMS
        [HttpPost]
        public async Task<IActionResult> SendSMS(string smsPhone, int id, string decryptedPassword)
        {
            var password = await _context.Passwords.FirstOrDefaultAsync(m => m.Id == id);
            if (password == null)
            {
                // Handle the case where the password is not found
                return Problem($"Cannot find password with id: {id} "); // Replace "Error" with the name of your error view
            }
            decryptedPassword = CryptorService.Cryptor.DecryptString(password.EncryptedPassword, _configuration["EncryptionKey"] ?? "");
            if (decryptedPassword == null) 
            { 
                return Problem ("Cannot decrypt password.");
            }
            var passwordDetails = new PasswordDetailsViewModel
            {
                Id = password.Id,
                Username = password.Username,
                Servername = password.Servername,
                DecryptedPassword = decryptedPassword
            };
            SendSMSService sendSMSService = new SendSMSService(_configuration);
            string result = await sendSMSService.SendSMSAsync(smsPhone, decryptedPassword);
            ViewData["Message"] = result;
            return View("Details", passwordDetails);
        }
        private bool PasswordExists(int id)
        {
            return _context.Passwords.Any(e => e.Id == id);
        }
    }
}
