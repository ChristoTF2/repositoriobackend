using System.Reflection;
using _1_API.Mapper;
using _2_Domain.IAM.CommandServices;
using Application;
using Application.IAM.CommandServices;
using Domain;
using Infraestructure;
using Infraestructure.Contexts;
using Infrastructure;
using LearningCenter.Domain.Blog.Services;
using LearningCenter.Domain.IAM.Repositories;
using LearningCenter.Domain.IAM.Services;
using LearningCenter.Infraestructure.IAM.Persistence;
using LearningCenter.Presentation.Middleware;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

//Ad cors

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllPolicy", 
        policy => policy.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader());
});


// Add services to the container.

builder.Services.AddHttpContextAccessor();

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = "v1",
        Title = "APis form mange AgroSolutions",
        Description = "An ASP.NET Core Web API for managing ToDo finance",
        TermsOfService = new Uri("https://example.com/terms"),
        Contact = new OpenApiContact
        {
            Name = "Example Contact",
            Url = new Uri("https://example.com/contact")
        },
        License = new OpenApiLicense
        {
            Name = "Example License",
            Url = new Uri("https://example.com/license")
        }
    });
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "bearer"
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            },
            Array.Empty<string>()
        }
    });

    
    var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    options.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));
    
});

//dependency inyection
builder.Services.AddScoped<IFinanceRepository, FinanceRepository>();
builder.Services.AddScoped<IFinanceCommandService, FinanceCommandService>();
builder.Services.AddScoped<IFinanceQueryService, FinanceQueryService>();

builder.Services.AddScoped<IPendingCollectionsRepository, PendingCollectionsRepository >();
builder.Services.AddScoped<IPendingCollectionsCommandService, PendingCollectionsCommandService>();
builder.Services.AddScoped<IPendingCollectionsQueryService, PendingCollectionsQueryService>();

builder.Services.AddScoped<ICropRepository, CropRepository>();
builder.Services.AddScoped<ICropCommandService, CropCommandService>();
builder.Services.AddScoped<ICropQueryService, CropQueryService>();

builder.Services.AddScoped<IUserRepository,UserRepository>();
builder.Services.AddScoped<IUserCommandService,UserCommandService>();
builder.Services.AddScoped<IEncryptService,EncryptService>();
builder.Services.AddScoped<ITokenService,TokenService>();
builder.Services.AddScoped<IUserQueryService,UserQueryService>();

builder.Services.AddScoped<IPendingRepository, PendingRepository>();
builder.Services.AddScoped<IPendingCommandService, PendingCommandService>();
builder.Services.AddScoped<IPendingQueryService, PendingQueryService>();


builder.Services.AddScoped<IEmployeeRepository, EmployeeRepository>();
builder.Services.AddScoped<IEmployeeCommandService, EmployeeCommandService>();
builder.Services.AddScoped<IEmployeeQueryService, EmployeeQueryService>();

builder.Services.AddScoped<ITeamRepository, TeamRepository>();
builder.Services.AddScoped<ITeamCommandService, TeamCommandService>();
builder.Services.AddScoped<ITeamQueryService, TeamQueryService>();

builder.Services.AddScoped<IBlogRepository, BlogRepository>();
builder.Services.AddScoped<IBlogCommandService, BlogCommandService>();
builder.Services.AddScoped<IBlogQueryService, BlogQueryService>();

//AUtomapper
builder.Services.AddAutoMapper(
    typeof(RequestToModels),
    typeof(ModelsToRequest),
    typeof(ModelsToResponse));

//Conexion a MySQL 
var connectionString = builder.Configuration.GetConnectionString("agrosolutions");
var serverVersion = new MySqlServerVersion(new Version(8, 0, 29));

builder.Services.AddDbContext<AgroSolutionsContext>(
    dbContextOptions =>
    {
        dbContextOptions.UseMySql(connectionString,
            ServerVersion.AutoDetect(connectionString)
        );
    });

//Auth
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer();
    
var app = builder.Build();

app.UseMiddleware<ErrorHandlerMiddleware>();

using (var scope = app.Services.CreateScope())
using (var context = scope.ServiceProvider.GetService<AgroSolutionsContext>())
{
    context.Database.EnsureCreated();
}


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.UseMiddleware<AuthenticationMiddleware>();

app.UseCors("AllowAllPolicy");

app.Run();