using System.Net.Mime;
using _1_API.Response;
using Agrosolutions.Domain.Crops.Model.Queries;
using AutoMapper;
using Domain;
using LearningCenter.Presentation.Filters;
using Microsoft.AspNetCore.Mvc;
using Presentation.Request;

namespace Presentation.Controllers;

[Route("api/[controller]")]
[ApiController]
public class CropController : ControllerBase
{
    private readonly IMapper _mapper;
    private readonly ICropCommandService _cropCommandService;
    private readonly ICropQueryService _cropQueryService;
    
    public CropController(ICropQueryService cropQueryService, ICropCommandService cropCommandService, IMapper mapper)
    {
        _cropQueryService = cropQueryService;
        _cropCommandService = cropCommandService;
        _mapper = mapper;
    }
    
    
    /// <summary>
    /// Creates a new calendar.
    /// </summary>
    /// <returns>Returns the ID of the created calendar or an error if creation fails.</returns>
    /// <response code="201">If the calendar is successfully created, returns the ID of the calendar.</response>
    /// <response code="400">If there is an issue with the request, returns a BadRequest error.</response>
    /// <response code="409">If there is a conflict in creating the calendar, returns a Conflict error.</response>
    /// <response code="500">If there is an internal server error, returns an InternalServerError error.</response>
    [HttpPost("Calendar")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [Produces(MediaTypeNames.Application.Json)]
    [CustomAuthorize("Farmer")]
    public async Task<IActionResult> PostCalendarAsync([FromBody] CreateCalendarCommand command)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        var result = await _cropCommandService.Handle(command);

        if (result > 0)
            return StatusCode(StatusCodes.Status201Created, result);

        return BadRequest();
    }
    
    
    /// <summary>
    /// Creates new crops.
    /// </summary>
    /// <param name="command">The command to create crops.</param>
    /// <returns>Returns the ID of the created crops or an error if they cannot be created.</returns>
    /// <response code="201">If the crops are successfully created, returns the crops' ID.</response>
    /// <response code="400">If there is a problem with the request, returns a BadRequest error.</response>
    /// <response code="409">If there is a conflict when creating the crops, returns a Conflict error.</response>
    /// <response code="500">If there is an internal server error, returns an InternalServerError error.</response>
    [HttpPost("Crops")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [Produces(MediaTypeNames.Application.Json)]
    [CustomAuthorize("Farmer")]
    public async Task<IActionResult> PostCropsAsync([FromBody] CreateCropsCommand command)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        var result = await _cropCommandService.Handle(command);

        if (result > 0)
            return StatusCode(StatusCodes.Status201Created, result);

        return BadRequest();
    }

    
    /// <summary>
    /// Creates a new advisor.
    /// </summary>
    /// <param name="command">The command to create an advisor.</param>
    /// <returns>Returns the ID of the created advisor or an error if it cannot be created.</returns>
    /// <response code="201">If the advisor is successfully created, returns the advisor's ID.</response>
    /// <response code="400">If there is a problem with the request, returns a BadRequest error.</response>
    /// <response code="409">If there is a conflict when creating the advisor, returns a Conflict error.</response>
    /// <response code="500">If there is an internal server error, returns an InternalServerError error.</response>
    [HttpPost("Adviser")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [Produces(MediaTypeNames.Application.Json)]
    [CustomAuthorize("Farmer")]
    public async Task<IActionResult> PostAdviserAsync([FromBody] CreateAdviserCommand command)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        var result = await _cropCommandService.Handle(command);

        if (result > 0)
            return StatusCode(StatusCodes.Status201Created, result);

        return BadRequest();
    }

    
    /// <summary>
    /// Retrieves all advisors.
    /// </summary>
    /// <returns>Returns a list of advisors or an error if none are found.</returns>
    /// <response code="200">If advisors are found, returns the list of advisors.</response>
    /// <response code="404">If no advisors are found, returns a NotFound error.</response>
    [HttpGet("Advisers")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [Produces(MediaTypeNames.Application.Json)]
    [CustomAuthorize("Farmer")]
    public async Task<IActionResult> GetAllAdvisersAsync()
    {
        var result = await _cropQueryService.Handle(new GetAllAsesoresQuery());
        if (result == null || result.Count == 0) return NotFound();
        return Ok(result);
    }

    
    /// <summary>
    /// Retrieves an advisor by their identifier.
    /// </summary>
    /// <param name="id">Enter the id of the advisor to retrieve:</param>
    /// <returns>Returns the advisor if found or an error if not found.</returns>
    /// <response code="200">If the advisor is found, returns the advisor.</response>
    /// <response code="404">If the advisor is not found, returns a NotFound error.</response>
    [HttpGet("Adviser/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [Produces(MediaTypeNames.Application.Json)]
    [CustomAuthorize("Farmer")]
    public async Task<IActionResult> GetAdviserAsync(int id)
    {
        var result = await _cropQueryService.Handle(new GetAsesorByIdQuery(id));
        if (result == null) StatusCode(StatusCodes.Status404NotFound);
        return Ok(result);
    }
    
    /// <summary>
    /// Retrieves a calendar by its identifier.
    /// </summary>
    /// <param name="id">Enter the id of the calendar to retrieve:</param>
    /// <returns>Returns the calendar if found or an error if not found.</returns>
    /// <response code="200">If the calendar is found, returns the calendar.</response>
    /// <response code="404">If the calendar is not found, returns a NotFound error.</response>
    [HttpGet("Calendar/ById/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [Produces(MediaTypeNames.Application.Json)]
    [CustomAuthorize("Farmer")]
    public async Task<IActionResult> GetCalendarByIdAsync(int id)
    {
        var result = await _cropQueryService.Handle(new GetCalendarioByIdQuery(id));
        if (result == null) StatusCode(StatusCodes.Status404NotFound);
        return Ok(result);
    }

    /// <summary>
    /// Retrieves the crops by their identifier.
    /// </summary>
    /// <param name="id">Enter the id of the crops to retrieve:</param>
    /// <returns>Returns the crops if found or an error if not found.</returns>
    /// <response code="200">If the crops are found, returns the crops.</response>
    /// <response code="404">If the crops are not found, returns a NotFound error.</response>
    [HttpGet("Crops/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [Produces(MediaTypeNames.Application.Json)]
    [CustomAuthorize("Farmer")]
    public async Task<IActionResult> GetCropsAsync(int id)
    {
        var result = await _cropQueryService.Handle(new GetCultivoByIdQuery(id));
        if (result == null) StatusCode(StatusCodes.Status404NotFound);
        return Ok(result);
    }

    
    /// <summary>
    /// Retrieves all calendars for a specific crop.
    /// </summary>
    /// <param name="cultivoId">Enter the id of the crop to retrieve the calendars for:</param>
    /// <returns>Returns a list of calendars or an error if none are found.</returns>
    /// <response code="200">If calendars are found, returns the list of calendars.</response>
    /// <response code="404">If no calendars are found, returns a NotFound error.</response>
    [HttpGet("Calendar/{cultivoId}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [Produces(MediaTypeNames.Application.Json)]
    [CustomAuthorize("Farmer")]
    public async Task<IActionResult> GetCalendarsForCultivoAsync(int cultivoId)
    {
        var result = await _cropQueryService.Handle(new GetAllCalendariosForCultivoQuery(cultivoId));
        if (result == null || result.Count == 0) return NotFound();
        return Ok(result);
    }
    
    
    /// <summary>
    /// Retrieves all crops.
    /// </summary>
    /// <returns>Returns a list of crops or an error if none are found.</returns>
    /// <response code="200">If crops are found, returns the list of crops.</response>
    /// <response code="404">If no crops are found, returns a NotFound error.</response>
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [Produces(MediaTypeNames.Application.Json)]
    [CustomAuthorize("Farmer")]
    public async Task<IActionResult> GetAllCropsAsync()
    {
        var result = await _cropQueryService.Handle(new GetAllCultivosQuery());
        if (result == null || result.Count == 0) return NotFound();
        return Ok(result);
    }
}
