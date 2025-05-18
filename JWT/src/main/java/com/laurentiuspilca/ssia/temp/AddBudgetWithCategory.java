package com.laurentiuspilca.ssia.temp;

public class AddBudgetWithCategory {
    public MonthlyBudget createMonthlyBudgetWithCategories(MonthlyBudgetRequestDTO dto) {
        Long userId = getCurrentUserId();

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        MonthlyBudget monthlyBudget = mapper.toEntity(dto);
        monthlyBudget.setUser(user);

        monthlyBudget = monthlyBudgetRepository.save(monthlyBudget); // Save first to get ID

        List<MonthlyCategoryBudget> categories = dto.getCategoryBudgets().stream()
                .map(categoryDTO -> {
                    MonthlyCategoryBudget entity = mapper.toEntity(categoryDTO);
                    entity.setMonthlyBudget(monthlyBudget); // manually wire
                    return entity;
                })
                .collect(Collectors.toList());

        monthlyCategoryBudgetRepository.saveAll(categories);

        return monthlyBudget;
    }

}
