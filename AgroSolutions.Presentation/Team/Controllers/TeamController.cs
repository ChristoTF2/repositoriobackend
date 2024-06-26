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
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Presentation.Request;

namespace Presentation
{
    [Route("api/v1/[controller]")]
    [ApiController]
    public class TeamController : ControllerBase
    {
        private readonly IMapper _mapper;
        private readonly ITeamCommandService _teamCommandService;
        private readonly ITeamQueryService _teamQueryService;

        public TeamController(ITeamCommandService teamCommandService,
            ITeamQueryService teamQueryService,
            IMapper mapper)
        {
            _teamCommandService = teamCommandService;
            _teamQueryService = teamQueryService;
            _mapper = mapper;
        }

        // GET: api/Team
        ///<summary>Obtain all the active Team</summary>
        /// <remarks>
        /// GET /api/Team
        ///   </remarks>
        /// <response code="200">Returns all the Team</response>
        /// <response code="404">If there are no Team</response>
        /// <response code="500">If there is an internal server error</response>
        [HttpGet]
        [ProducesResponseType(typeof(List<TeamResponse>), 200)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> GetAsync()
        {
            var result = await _teamQueryService.Handle(new GetAllTeamQuery());
            if (result.Count == 0) return NotFound();
            return Ok(result);
        }

        /// GET: api/v1/Team/5
        ///<summary>Obtain the active teams</summary>
        /// <remarks>
        /// GET: api/v1/Team/5
        ///   </remarks>
        /// <response code="200">Returns all the team</response>
        /// <response code="404">If there are no team</response>
        /// <response code="500">If there is an internal server error</response>
        [ProducesResponseType( typeof(List<TeamResponse>), 200)]
        [ProducesResponseType( typeof(void),StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [HttpGet("{id}", Name = "GetTeam")]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> GetAsync(int id)
        {
            var result = await _teamQueryService.Handle(new GetByIdTeamQuery(id));
            if (result==null) StatusCode(StatusCodes.Status404NotFound);
            return Ok(result);
        }

        // POST: api/v1/Team
        /// <summary>
        /// Creates a new Team.
        /// </summary>
        /// <remarks>
        /// POST api/v1/Team
        ///</remarks>
        /// Sample request:
        ///
        ///     {
        ///         "teamCode": "n8Eo",
        ///    "budget": 1000000000,
        ///    "cropCode": "5u7aneungY",
        ///    "advicers": [
        ///    {
        ///        "name": "Mario",
        ///        "dni": "81255660"
        ///    }
        ///    ],
        ///    "producers": [
        ///    {
        ///        "name": "Maria",
        ///        "dni": "00843799"
        ///    }
        ///    ]
        /// }
        /// </remarks>
        /// <param name="CreateTeamCommand">The Team to create</param>
        /// <returns>A newly created Team</returns>
        /// <response code="201">Returns the newly created Team</response>
        /// <response code="400">If the Team has invalid property</response>
        /// <response code="409">Error validating data</response>
        /// <response code="500">Unexpected error</response>
        [ProducesResponseType(typeof(int), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
        [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [HttpPost]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> PostAsync([FromBody] CreateTeamCommand command)
        {
            if (!ModelState.IsValid) return BadRequest();
            var result = await _teamCommandService.Handle(command);

            if (result > 0)
                return StatusCode(StatusCodes.Status201Created, result);

            return BadRequest();
        }

        
        /// DELETE: api/v1/Team/5
        ///<summary>Obtain the active teams</summary>
        /// <remarks>
        /// DELETE api/v1/Team/5
        ///   </remarks>
        /// <response code="200">Returns delete the team</response>
        /// <response code="404">If there are no team</response>
        /// <response code="500">If there is an internal server error</response>
        [ProducesResponseType( typeof(List<TeamResponse>), 200)]
        [ProducesResponseType( typeof(void),StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [HttpDelete("{id}")]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> DeleteAsync(int id)
        {
            DeleteTeamCommand command = new DeleteTeamCommand { Id = id };
            var result = await _teamCommandService.Handle(command);
            return Ok();
        }
    }
}
