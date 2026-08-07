using LinuxPass.Data;
using LinuxPass.Models;
using LinuxPass.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LinuxPass.Controllers
{
    [Authorize(Roles = "Admin")]
    public class PasswordsController : Controller
    {
        private readonly LinuxPassMngContext _context;
        private readonly IConfiguration _configuration;
        private readonly SendSMSService _sendSMSService;

        public PasswordsController(LinuxPassMngContext context, IConfiguration configuration, SendSMSService sendSMSService)
        {
            _context = context;
            _configuration = configuration;
            _sendSMSService = sendSMSService;
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

            if (!string.IsNullOrEmpty(searchString))
            {
                passwords = passwords.Where(s => s.Username!.ToUpper().Contains(searchString.ToUpper()));
            }
            if (!string.IsNullOrEmpty(searchString2))
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
                string encryptionKey = _configuration["EncryptionKey"] ?? string.Empty;
                string encryptedPassword = password.EncryptedPassword ?? string.Empty;
                string decryptedpass = CryptorService.Cryptor.DecryptString(encryptedPassword, encryptionKey);
                var passwordDetails = new PasswordDetailsViewModel
                {
                    Id = password.Id,
                    Username = password.Username ?? string.Empty,
                    Servername = password.Servername ?? string.Empty,
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

            string sshKeypath = _configuration["SSHKeyPath"] ?? string.Empty;
            var sshUser = await _context.Servers.FirstOrDefaultAsync(s => s.HostSrvName == password.Servername);
            if (sshUser == null)
            {
                ViewData["Message"] = "Server not found.";
                return View(password);
            }

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
                password.EncryptedPassword = CryptorService.Cryptor.EncryptString(generatedpass, _configuration["EncryptionKey"] ?? string.Empty);
                password.AddTime = DateTime.Now;
                _context.Add(password);
                await _context.SaveChangesAsync();
                ViewData["Message"] = "User created successfully.";
                return View(password);
            }

            ViewData["Message"] = result;
            return View(password);
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
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendSMS(string smsPhone, int id)
        {
            var password = await _context.Passwords.FirstOrDefaultAsync(m => m.Id == id);
            if (password == null)
            {
                return Problem($"Cannot find password with id: {id}");
            }

            string decryptedPassword = CryptorService.Cryptor.DecryptString(
                password.EncryptedPassword ?? string.Empty,
                _configuration["EncryptionKey"] ?? string.Empty);

            var passwordDetails = new PasswordDetailsViewModel
            {
                Id = password.Id,
                Username = password.Username ?? string.Empty,
                Servername = password.Servername ?? string.Empty,
                DecryptedPassword = decryptedPassword
            };

            string result = await _sendSMSService.SendSMSAsync(smsPhone);
            ViewData["Message"] = result;
            return View("Details", passwordDetails);
        }
    }
}
