using System.Data;
using AutoMapper;
using Domain;
using Infraestructure;
using Presentation.Request;
using Shared;

namespace Application;

public class FinanceCommandService : IFinanceCommandService
{
    private readonly IFinanceRepository _financeRepository;
    private readonly IMapper _mapper;

    public FinanceCommandService(IFinanceRepository financeRepository, IMapper mapper)
    {
        _financeRepository = financeRepository;
        _mapper = mapper;
    }

    public async Task<int> Handle(CreateFinanceCommand command)
    {
        var finance = _mapper.Map<CreateFinanceCommand, Finance>(command);

        var existingFinance = await _financeRepository.GetByMonthAsync(finance.Month);
        if (existingFinance != null) throw new DuplicateNameException("Finance already exists");

        var total = (await _financeRepository.GetAllAsync()).Count;
        if (total >= Constants.MAX_TUTORIALS)
            throw new ConstraintException("Max finances reached " + Constants.MAX_TUTORIALS);

        return await _financeRepository.SaveAsync(finance);
    }

    public async Task<bool> Handle(UpdateFinanceCommand command)
    {
        var existingFinance = await _financeRepository.GetById(command.Id);
        var finance = _mapper.Map<UpdateFinanceCommand, Finance>(command);

        if (existingFinance == null) throw new NotException("Finance not found");

        if (existingFinance.Month != finance.Month)
            throw new ConstraintException("Description can not be updated");

        return await _financeRepository.Update(finance, finance.Id);
    }

    public async Task<bool> Handle(DeleteFinanceCommand command)
    {
        var existingFinance = _financeRepository.GetById(command.Id);
        if (existingFinance == null) throw new NotException("Finance not found");
        return await _financeRepository.Delete(command.Id);
    }
}