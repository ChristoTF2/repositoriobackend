using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mime;
using System.Threading.Tasks;
using _1_API.Response;
using AutoMapper;
using Domain;
using Infrastructure;
using LearningCenter.Domain.Publishing.Models.Queries;
using LearningCenter.Presentation.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Presentation.Request;

namespace Presentation.Controllers
{
    [Route("api/v1/[controller]")]
    [ApiController]
    public class PendingController : ControllerBase
    {
        
        private readonly IMapper _mapper;
        private readonly IPendingCommandService _pendingCommandService;
        private readonly IPendingQueryService _pendingQueryService;

        public PendingController(IPendingCommandService pendingCommandService, IPendingQueryService pendingQueryService,
            IMapper mapper)
        {
            _pendingCommandService = pendingCommandService;
            _pendingQueryService = pendingQueryService;
            _mapper = mapper;
        }
        
        // GET: api/v1/Pending
        ///<summary>Obtain all the active pending</summary>
        /// <remarks>
        /// GET /api/Pending
        ///   </remarks>
        /// <response code="200">Returns all the pending</response>
        /// <response code="404">If there are no pending</response>
        /// <response code="500">If there is an internal server error</response>
        [HttpGet]
        [ProducesResponseType( typeof(List<PendingResponse>), 200)]
        [ProducesResponseType( typeof(void),StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [CustomAuthorize("Seller, Farmer")]
        public async Task<IActionResult> GetAsync()
        {
            var result = await _pendingQueryService.Handle(new GetAllPendingQuery());
            if (result.Count == 0) return NotFound();
            return Ok(result);
        } 
        
        
        // GET: api/v1/Pending/Search
        ///<summary>Obtain all the active pending</summary>
        /// <remarks>
        /// GET /api/Pending
        ///   </remarks>
        /// <response code="200">Returns the pending</response>
        /// <response code="404">If there are no pending</response>
        /// <response code="500">If there is an internal server error</response>
        [HttpGet]
        [ProducesResponseType( typeof(List<PendingResponse>), 200)]
        [ProducesResponseType( typeof(void),StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [Route("Search")]
        [CustomAuthorize("Farmer")]
        public async Task<IActionResult> GetSearchAsync(string? priority, string? category, string? stateOfTask)
        {
            var result = await _pendingQueryService.Handle(new GetPendingSearchQuery(priority, category, stateOfTask ));
            if (result==null) StatusCode(StatusCodes.Status404NotFound);

            return Ok(result);
        }
        
        // GET: api/v1/Pending/5
        ///<summary>Obtain all the active pending</summary>
        /// <remarks>
        /// GET api/v1/Pending/5
        ///   </remarks>
        /// <response code="200">Returns the pending</response>
        /// <response code="404">If there are no pending</response>
        /// <response code="500">If there is an internal server error</response>
        [ProducesResponseType( typeof(List<PendingResponse>), 200)]
        [ProducesResponseType( typeof(void),StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [HttpGet("{id}", Name = "GetPendingById")]
        [CustomAuthorize("Farmer")]
        public  async Task<IActionResult> GetPendingByIdAsync(int id)
        {
            var result = await _pendingQueryService.Handle(new GetByIdPendingQuery(id));
            if (result==null) StatusCode(StatusCodes.Status404NotFound);
            return Ok(result);
            
        }
        
        // POST: api/v1/Pending
        /// <summary>
        /// Creates a new Pending.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/Account
        ///     {
        ///     "name": "Project",
        ///     "descriptionTask": "Description",
        ///     "dueDate": "2025-06-07",
        ///     "assignedTo": "Maria",
        ///     "priority": " High-Medium-Low",
        ///     "category": "Crop-Production-Operation-Distribution-Market-Specialization",
        ///     "state": "Done-ToDo-Doing",
        ///     }
        ///
        /// </remarks>
        /// <param name="CreatePendingCommand">The Pending to create</param>
        /// <returns>A newly created Pending</returns>
        /// <response code="201">Returns the newly created Pending</response>
        /// <response code="400">If the Pending has invalid property</response>
        /// <response code="409">Error validating data</response>
        /// <response code="500">Unexpected error</response>
        [HttpPost]
        [ProducesResponseType(typeof(int), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
        [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [CustomAuthorize("Admin", "Farmer")]
        public async Task<IActionResult> PostAsync([FromBody] CreatePendingCommand command)
        {
            if (!ModelState.IsValid) return BadRequest();
            var result = await _pendingCommandService.Handle(command);

            if (result > 0)
                return StatusCode(StatusCodes.Status201Created, result);

            return BadRequest();
        }


        // POST: api/v1/Pending/5
        /// <summary>
        /// Update a Pending.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/Account
        ///     {
        ///     "descriptionTask": "Description",
        ///     "dueDate": "2025-06-07",
        ///     "assignedTo": "Maria",
        ///     "category": "Crop-Production-Operation-Distribution-Market-Specialization",
        ///     "state": "Done-ToDo-Doing",
        ///     }
        ///
        /// </remarks>
        /// <param name="CreatePendingCommand">The Pending to create</param>
        /// <returns>A newly update Pending</returns>
        /// <response code="201">Returns the newly update Pending</response>
        /// <response code="400">If the Pending has invalid property</response>
        /// <response code="409">Error validating data</response>
        /// <response code="500">Unexpected error</response>
        [HttpPut("{id}")]
        [ProducesResponseType(typeof(int), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
        [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [CustomAuthorize("Farmer")]
        public async Task<IActionResult> PutAsync(int id, [FromBody] UpdatePendingCommand command)
        {
            if (ModelState.IsValid)
            {
                command.Id = id;
                if (!ModelState.IsValid) return StatusCode(StatusCodes.Status400BadRequest);
                var result = await _pendingCommandService.Handle(command);
                return Ok();
            }
            return StatusCode(StatusCodes.Status400BadRequest);
        }

        // DELETE: api/v1/Pending/5
        ///<summary>Obtain all the active pending</summary>
        /// <remarks>
        /// DELETE: api/v1/Pending/5
        ///   </remarks>
        /// <response code="200">Returns all the pending</response>
        /// <response code="404">If there are no pending</response>
        /// <response code="500">If there is an internal server error</response>
        [ProducesResponseType( typeof(List<PendingResponse>), 200)]
        [ProducesResponseType( typeof(void),StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [HttpDelete("{id}")]
        [CustomAuthorize("Farmer")]
        public async Task<IActionResult> DeleteAsync(int id)
        {
            DeletePendingCommand command = new DeletePendingCommand { Id = id };
            var result = await _pendingCommandService.Handle(command);
            return Ok();
        }
    }
}
