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

namespace Presentation.Controllers;

[Route("api/[controller]")]
[ApiController]
public class FinanceController : ControllerBase
{
    private readonly IMapper _mapper;
    private readonly IFinanceCommandService _financeCommandService;
    private readonly IFinanceQueryService _financeQueryService;

    public FinanceController(IFinanceQueryService financeQueryService, IFinanceCommandService financeCommandService,
        IMapper mapper)
    {
        _financeQueryService = financeQueryService;
        _financeCommandService = financeCommandService;
        _mapper = mapper;
    }


    // GET: api/Finance
    ///<summary>Obtain all the active finances</summary>
    /// <remarks>
    /// GET /api/Finance
    ///   </remarks>
    /// <response code="200">Returns all the finances</response>
    /// <response code="404">If there are no finances</response>
    /// <response code="500">If there is an internal server error</response>
    [HttpGet]
    [ProducesResponseType( typeof(List<FinanceResponse>), 200)]
    [ProducesResponseType( typeof(void),StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
    [Produces(MediaTypeNames.Application.Json)]
    [CustomAuthorize("Farmer")]

    public async Task<IActionResult> GetAsync()
    {
        var result = await _financeQueryService.Handle(new GetAllFinancesQuery());
        
        if (result.Count == 0) return NotFound();

        return Ok(result);
    }

    // GET: api/Finance/Search
    [HttpGet]
    [Route("Search")]
    [CustomAuthorize("Farmer")]

    public async Task<IActionResult> GetSearchAsync(string? name)
    {
        //var data = await _financeRepository.GetSearchAsync(name, year);

        var result = await _financeQueryService.Handle(new GetAllFinancesQuery());
        if (result.Count == 0) return NotFound();

        return Ok(result);
    }

    // GET: api/Finance/5
    [HttpGet("{id}", Name = "GetAsync")]
    [CustomAuthorize("Farmer")]
    public async Task<IActionResult> GetAsync(int id)
    {
        var result = await _financeQueryService.Handle(new GetFinancesByIdQuery(id));

        if (result==null) StatusCode(StatusCodes.Status404NotFound);
        
        return Ok(result);
    }

    // POST: api/Finance
    // POST: api/Finance
    /// <summary>
    /// Creates a new Finance.
    /// </summary>
    /// <remarks>
    /// Sample request:
    ///
    ///     POST /api/Finance
    ///     {
    ///        "month": "New finance",
    ///        "incomes": "12000"
    ///        "bills": "8000"
    ///        "earning": "4000"
    /// 
    ///     }
    ///
    /// </remarks>
    /// <param name="CreateFinanceCommand">The finance to create</param>
    /// <returns>A newly created finance</returns>
    /// <response code="201">Returns the newly created finance</response>
    /// <response code="400">If the finance has invalid property</response>
    /// <response code="409">Error validating data</response>
    /// <response code="500">Unexpected error</response>
    [HttpPost]
    [ProducesResponseType(typeof(int), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
    [Produces(MediaTypeNames.Application.Json)]
    [CustomAuthorize("Farmer")]
    public async Task<IActionResult> PostAsync([FromBody] CreateFinanceCommand command)
    {
        if (!ModelState.IsValid) return BadRequest();


        var result = await _financeCommandService.Handle(command);

        //if (result > 0)
            return StatusCode(StatusCodes.Status201Created, result);

        //return BadRequest();
    }

    // PUT: api/Finance/5
    [HttpPut("{id}")]
    [CustomAuthorize("Farmer")]

    public async Task<IActionResult> PutAsync(int id, [FromBody] UpdateFinanceCommand command)
    {
        command.Id = id;
        if (!ModelState.IsValid) return StatusCode(StatusCodes.Status400BadRequest);

        var result = await _financeCommandService.Handle(command);

        return Ok();
    }

    // DELETE: api/Finance/5
    [HttpDelete("{id}")]
    [CustomAuthorize("Farmer")]

    public async Task<IActionResult> DeleteAsync(int id)
    {
        DeleteFinanceCommand command = new DeleteFinanceCommand { Id = id };

        var result = await _financeCommandService.Handle(command);

        return Ok();
    }
}