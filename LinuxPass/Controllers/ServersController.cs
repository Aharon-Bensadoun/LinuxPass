using LinuxPass.Data;
using LinuxPass.Models;
using LinuxPass.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LinuxPass.Controllers
{
    public class ServersController : Controller
    {
        private readonly LinuxPassMngContext _context;
        private readonly IConfiguration _configuration;

        public ServersController(LinuxPassMngContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public async Task<IActionResult> Index(string searchString)
        {
            if (_context.Servers == null)
            {
                return Problem("Entity set ServersContext is null.");
            }

            var servers = from m in _context.Servers
                          select m;

            if (!String.IsNullOrEmpty(searchString))
            {
                servers = servers.Where(s => s.HostSrvName!.ToUpper().Contains(searchString.ToUpper()));
            }

            var uniqueservers = await servers
                .GroupBy(s => new { s.HostSrvUsername, s.HostSrvName })
                .Select(g => g.FirstOrDefault())
                .ToListAsync();

            return View(uniqueservers);
        }

        // GET: Servers/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var server = await _context.Servers
                .FirstOrDefaultAsync(m => m.Id == id);
            if (server == null)
            {
                return NotFound();
            }

            return View(server);
        }

        // GET: Servers/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Servers/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,HostSrvName,HostSrvUsername,HostSrvPassword,HostSSHKeyPath")] Server server)
        {
            if (ModelState.IsValid)
            {
                if (server.HostSrvPassword == null)
                {
                    ViewData["Message"] = "Password cannot be null.";
                    return View(server);
                }
                // Check if the server name already exists
                var existingServer = await _context.Servers
                    .FirstOrDefaultAsync(s => s.HostSrvName == server.HostSrvName);

                if (existingServer != null)
                {
                    ViewData["Message"] = "Server name already exists.";
                    return View(server);
                }
                AddServerService addServerService = new AddServerService(_context, _configuration);
                string result = addServerService.ResetPass(server.HostSrvName, server.HostSrvUsername, server.HostSrvPassword);
                if (result == "Success")
                {
                    var newServer = new Server
                    {
                        HostSrvName = server.HostSrvName,
                        HostSrvUsername = server.HostSrvUsername
                    };

                    _context.Add(newServer);
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                else
                {
                    ViewData["Message"] = result;
                    return View(server);
                }
            }
            return View(server);
        }

        // GET: Servers/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var server = await _context.Servers.FindAsync(id);
            if (server == null)
            {
                return NotFound();
            }
            return View(server);
        }

        // POST: Servers/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,HostSrvName,HostSrvUsername,HostSrvPassword,HostSSHKeyPath")] Server server)
        {
            if (id != server.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    if (server.HostSrvPassword == null)
                    {
                        ViewData["Message"] = "Password cannot be null.";
                        return View(server);
                    }
                    AddServerService addServerService = new AddServerService(_context, _configuration);
                    string result = addServerService.ResetPass(server.HostSrvName, server.HostSrvUsername, server.HostSrvPassword);
                    if (result == "Success")
                    {
                        var newServer = new Server
                        {
                            HostSrvName = server.HostSrvName,
                            HostSrvUsername = server.HostSrvUsername
                        };
                        _context.Update(server);
                        await _context.SaveChangesAsync();
                    }
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!ServerExists(server.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(server);
        }

        // GET: Servers/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var server = await _context.Servers
                .FirstOrDefaultAsync(m => m.Id == id);
            if (server == null)
            {
                return NotFound();
            }

            return View(server);
        }

        // POST: Servers/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var server = await _context.Servers.FindAsync(id);
            if (server != null)
            {
                _context.Servers.Remove(server);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Rotate(int id)
        {
            var server = await _context.Servers.FindAsync(id);
            string sshKey = _configuration["SSHKeyPath"] ?? "";
            if (server != null)
            {
                var servers = await _context.Servers.ToListAsync();
                var resetPassService = new ResetPassService(_context, _configuration);
                string result = await resetPassService.ResetPass(server.HostSrvName, server.HostSrvUsername, sshKey);
                if (result != "Success")
                {
                    ViewData["ErrorMessage"] = result;
                }
                else
                {
                    ViewData["Message"] = result;
                }
                return View("Index", servers);

            }
            return RedirectToAction(nameof(Index));
        }

        private bool ServerExists(int id)
        {
            return _context.Servers.Any(e => e.Id == id);
        }
    }
}
