using _1_API.Response;
using AutoMapper;
using Domain;
using LearningCenter.Domain.Publishing.Models.Queries;

namespace Application;

public class FinanceQueryService : IFinanceQueryService
{
    private readonly IFinanceRepository _financeRepository;
    private readonly IMapper _mapper;
    
    public FinanceQueryService(IFinanceRepository financeRepository,IMapper mapper)
    {
        _financeRepository = financeRepository;
        _mapper = mapper;
    }

    public async Task<List<FinanceResponse>?> Handle(GetAllFinancesQuery query)
    {
       var data =  await _financeRepository.GetAllAsync();
        var result = _mapper.Map<List<Finance>, List<FinanceResponse>>(data);
        return result;
    }

    public async Task<FinanceResponse?> Handle(GetFinancesByIdQuery query)
    {
        var data =  await _financeRepository.GetById(query.Id);
        var result = _mapper.Map<Finance, FinanceResponse>(data);
        return result;
    }
}