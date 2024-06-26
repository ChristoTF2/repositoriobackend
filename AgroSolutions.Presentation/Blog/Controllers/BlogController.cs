using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mime;
using System.Threading.Tasks;
using _1_API.Response;
using AutoMapper;
using Domain;
using Infrastructure;
using LearningCenter.Domain.Blog.Models.Commands;
using LearningCenter.Domain.Blog.Models.Entities;
using LearningCenter.Domain.Blog.Models.Queries;
using LearningCenter.Domain.Blog.Models.Response;
using LearningCenter.Domain.Blog.Services;
using LearningCenter.Domain.Publishing.Models.Queries;
using LearningCenter.Presentation.Filters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Presentation.Request;

namespace Presentation
{
    [Route("api/v1/[controller]")]
    [ApiController]
    public class BlogController : ControllerBase
    {
        private readonly IMapper _mapper;
        private readonly IBlogCommandService _blogCommandService;
        private readonly IBlogQueryService _blogQueryService;

        public BlogController(IBlogCommandService blogCommandService,
            IBlogQueryService blogQueryService,
            IMapper mapper)
        {
            _blogCommandService = blogCommandService;
            _blogQueryService = blogQueryService;
            _mapper = mapper;
        }

        // GET: api/v1/Blog
        ///<summary>Obtain all the active blog</summary>
        /// <remarks>
        /// GET api/v1/Blog
        ///   </remarks>
        /// <response code="200">Returns all the blog</response>
        /// <response code="404">If there are no blog</response>
        /// <response code="500">If there is an internal server error</response>
        [HttpGet]
        [ProducesResponseType(typeof(List<BlogShortResponse>), 200)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> GetAsync()
        {
            var result = await _blogQueryService.Handle(new GetAllBlogQuery());
            if (result.Count == 0) return NotFound();
            return Ok(result);
        }

        /// GET: api/v1/Blog/5
        ///<summary>Obtain the active Blog</summary>
        /// <remarks>
        /// GET: api/v1/Blog/5
        ///   </remarks>
        /// <response code="200">Returns all the Blog</response>
        /// <response code="404">If there are no Blog</response>
        /// <response code="500">If there is an internal server error</response>
        [ProducesResponseType( typeof(List<BlogResponse>), 200)]
        [ProducesResponseType( typeof(void),StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void),StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [HttpGet("{id}", Name = "GetBlog")]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> GetAsync(int id)
        {
            var result = await _blogQueryService.Handle(new GetByIdBlogQuery(id));
            if (result==null) StatusCode(StatusCodes.Status404NotFound);
            return Ok(result);
        }
        
        // GET: api/Blog/SearchRole
        ///<summary>Obtain all the active blog</summary>
        /// <remarks>
        /// GET api/Blog/SearchRole
        ///   </remarks>
        /// <response code="200">Returns all the blog</response>
        /// <response code="404">If there are no blog</response>
        /// <response code="500">If there is an internal server error</response>
        [HttpGet]
        [ProducesResponseType(typeof(List<BlogShortResponse>), 200)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status500InternalServerError)]
        [Produces(MediaTypeNames.Application.Json)]
        [Route("SearchRole")]
        [CustomAuthorize("Seller", "Farmer")]
        public async Task<IActionResult> GetByRoleBlogSearchAsync(string? RoleBlog)
        {
            var result = await _blogQueryService.Handle(new GetAllBlogQuery());
            if (result == null) StatusCode(StatusCodes.Status404NotFound);

            return Ok(result);
        }

        // POST: api/v1/Blog
        /// <summary>
        /// Creates a new Blog.
        /// </summary>
        /// <remarks>
        /// POST api/v1/Blog
        ///</remarks>
        /// Sample request:
        ///
        /// 
        /// </remarks>
        /// <param name="CreateTeamCommand">The Blog to create</param>
        /// <returns>A newly created Blog</returns>
        /// <response code="201">Returns the newly created Blog</response>
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
        public async Task<IActionResult> PostAsync([FromBody] CreateBlogCommand command)
        {
            if (!ModelState.IsValid) return BadRequest();
            var result = await _blogCommandService.Handle(command);

            if (result > 0)
                return StatusCode(StatusCodes.Status201Created, result);

            return BadRequest();
        }
    }
}
