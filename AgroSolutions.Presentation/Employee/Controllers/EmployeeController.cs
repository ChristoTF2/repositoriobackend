using System.Net.Mime;
using _1_API.Response;
using Application;
using Infraestructure;
using AutoMapper;
using Domain;
using LearningCenter.Domain.Publishing.Models.Queries;
using LearningCenter.Presentation.Filters;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.CodeAnalysis.Elfie.Serialization;
using Presentation.Request;

namespace Presentation.Publishing.Controllers
{
    [ApiController]
    [Route("api/v1/[controller]")]
    public class EmployeeController : ControllerBase
    {
        private readonly IMapper _mapper;
        private readonly IEmployeeCommandService _employeeCommandService;
        private readonly IEmployeeQueryService _employeeQueryService;

        public EmployeeController(IEmployeeCommandService employeeCommandService,
            IEmployeeQueryService employeeQueryService,
            IMapper mapper)
        {
            _employeeCommandService = employeeCommandService;
            _employeeQueryService = employeeQueryService;
            _mapper = mapper;
        }

        // GET: api/v1/employee
        ///<summary>Obtain all the active employee</summary>
        /// <remarks>
        /// GET /api/v1/employee
        ///   </remarks>
        /// <response code="200">Returns all the employee</response>
        /// <response code="404">If there are no employee</response>
        /// <response code="500">If there is an internal server error</response>
        [HttpGet]
        [ProducesResponseType(typeof(List<EmployeShortResponse>), 200)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> GetAsync()
        {
            var result = await _employeeQueryService.Handle(new GetAllEmployeesQuery());
            if (result.Count == 0) return NotFound();
            return Ok(result);
        }
        
        // GET: api/v1/employee/5
        ///<summary>Obtain all the active employee</summary>
        /// <remarks>
        /// GET /api/v1/employee/5
        ///   </remarks>
        /// <response code="200">Returns all the employee</response>
        /// <response code="404">If there are no employee</response>
        /// <response code="500">If there is an internal server error</response>
        [HttpGet("{id}", Name = "GetEmployee")]
        [ProducesResponseType(typeof(List<EmployeeResponse>), 200)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> GetAsync(int id)
        {
            var result = await _employeeQueryService.Handle(new GetByIdEmployeeQuery(id));
            if (result == null) StatusCode(StatusCodes.Status404NotFound);

            return Ok(result);
        }
        
        
        // GET: api/Employee/SearchAsyncJobAndTeam
        ///<summary>Obtain all the active employee</summary>
        /// <remarks>
        /// GET api/Employee/SearchAsyncJobAndTeam
        ///   </remarks>
        /// <response code="200">Returns all the employee</response>
        /// <response code="404">If there are no employee</response>
        /// <response code="500">If there is an internal server error</response>
        [HttpGet]
        [ProducesResponseType(typeof(List<EmployeShortResponse>), 200)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [Route("SearchJobAndTeam")]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> GetSearchAsyncJobAndTeam(string? job, int teamId)
        {
            var result = await _employeeQueryService.Handle(new GetByJobEmployeeQuery(job, teamId));
            if (result == null) StatusCode(StatusCodes.Status404NotFound);

            return Ok(result);
        }
        
        // GET: api/Employee/SearchJob
        ///<summary>Obtain all the active employee</summary>
        /// <remarks>
        /// GET api/Employee/SearchJob
        ///   </remarks>
        /// <response code="200">Returns all the employee</response>
        /// <response code="404">If there are no employee</response>
        /// <response code="500">If there is an internal server error</response>
        [HttpGet]
        [ProducesResponseType(typeof(List<EmployeShortResponse>), 200)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [Route("SearchJob")]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> GetSearchJobAsync(string? job)
        { 
            var result = await _employeeQueryService.Handle(new GetByJobSearchQuery(job));
            if (result==null) StatusCode(StatusCodes.Status404NotFound);
            return Ok(result);
        }
        
        // POST: api/Account
        /// <summary>
        /// Creates a new Account.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/Account
        ///{
        ///    "name": "vZToWilXWTcjXgeleiCXmkswk",
        ///    "lastName": "eVFMHJxPmiGXQGUjwukJ",
        ///    "age": 18,
        ///    "dni": "08924405",
        ///    "job": "Adviser",
        ///    "salary": 1000000,
        ///    "phone": "305005857",
        ///    "photoUrl": "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSfqsyPWhAJIYBSTZ_puwc2R_LkmSQvcoOfoQ&s",
        ///     }
        ///
        /// </remarks>
        /// <param name="CreateAccountCommand">The Account to create</param>
        /// <returns>A newly created Account</returns>
        /// <response code="201">Returns the newly created Account</response>
        /// <response code="400">If the Account has invalid property</response>
        /// <response code="409">Error validating data</response>
        /// <response code="500">Unexpected error</response>
        // POST: api/Employee
        [HttpPost]
        [ProducesResponseType(typeof(int), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
        [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> PostAsync([FromBody] CreateEmployeeCommand command)
        {
            if (!ModelState.IsValid) return BadRequest();
            var result = await _employeeCommandService.Handle(command);

            if (result > 0)
                return StatusCode(StatusCodes.Status201Created, result);

            return BadRequest();
        }
        
        // DELETE: api/v1/employee/5
        ///<summary>Obtain delete id from employee</summary>
        /// <remarks>
        /// DELETE /api/v1/employee/5
        ///   </remarks>
        /// <response code="200">Returns the delete employee</response>
        /// <response code="404">If there are no employee</response>
        /// <response code="500">If there is an internal server error</response>
        [HttpDelete("{id}")]
        [ProducesResponseType(typeof(List<EmployeeResponse>), 200)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> DeleteAsync(int id)
        {
            DeleteEmployeeCommand command = new DeleteEmployeeCommand { Id = id };
            var result = await _employeeCommandService.Handle(command);
            return Ok();
        }
    }
}
