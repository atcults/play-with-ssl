using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace PlayWithSSL.Controllers
{
    [Route("/data")]
    [ApiController]
    public class DataController : ControllerBase
    {
        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var data = new
            {
                Id = 1,
                Name = "Ivan",
                Age = 42
            };

            await Task.Delay(10);

            return Ok(data);
        }
    }
}
